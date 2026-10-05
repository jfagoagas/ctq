package ct

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strconv"
)

// Searcher looks up historical certificates through a CT aggregator.
type Searcher interface {
	Name() string
	Search(ctx context.Context, domain string, subdomains, includeExpired bool) ([]Certificate, error)
}

func warnf(w io.Writer, format string, args ...any) {
	if w != nil {
		fmt.Fprintf(w, "ctq: "+format+"\n", args...)
	}
}

// CrtSh queries crt.sh. One request, full history including expired certs,
// but its Postgres kills queries after ~10s, so big domains often fail.
type CrtSh struct {
	Client  *Client
	BaseURL string
}

func (CrtSh) Name() string { return "crtsh" }

type crtshRow struct {
	ID         int64  `json:"id"`
	IssuerName string `json:"issuer_name"`
	CommonName string `json:"common_name"`
	NameValue  string `json:"name_value"`
	NotBefore  string `json:"not_before"`
	NotAfter   string `json:"not_after"`
}

func (s CrtSh) Search(ctx context.Context, domain string, subdomains, includeExpired bool) ([]Certificate, error) {
	base := s.BaseURL
	if base == "" {
		base = "https://crt.sh/"
	}
	q := url.Values{"output": {"json"}, "deduplicate": {"Y"}, "q": {domain}}
	if subdomains {
		// crt.sh uses SQL LIKE syntax. Domain validation upstream keeps users from injecting their own %.
		q.Set("q", "%."+domain)
	}
	if !includeExpired {
		q.Set("exclude", "expired")
	}

	resp, err := s.Client.Get(ctx, base+"?"+q.Encode(), nil)
	if err != nil {
		return nil, fmt.Errorf("crt.sh: %w", err)
	}
	var rows []crtshRow
	if err := json.Unmarshal(resp.Body, &rows); err != nil {
		// crt.sh reports DB timeouts as HTML pages.
		return nil, fmt.Errorf("crt.sh: expected JSON, got %s", snippet(resp.Body))
	}

	certs := make([]Certificate, 0, len(rows))
	for _, r := range rows {
		names := Scope(append(splitLines(r.NameValue), r.CommonName), domain, subdomains)
		if len(names) == 0 {
			continue
		}
		nb, err1 := parseTime(r.NotBefore)
		na, err2 := parseTime(r.NotAfter)
		if err1 != nil || err2 != nil {
			continue
		}
		certs = append(certs, Certificate{
			ID: strconv.FormatInt(r.ID, 10), Source: s.Name(), Issuer: r.IssuerName,
			DNSNames: names, NotBefore: nb, NotAfter: na,
		})
	}
	return certs, nil
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return out
}

// CertSpotter queries SSLMate's Cert Spotter API. Reliable and paginated, but
// 10 requests/hour without an API key, and it only returns unexpired certificates.
type CertSpotter struct {
	Client   *Client
	BaseURL  string
	APIKey   string
	MaxPages int
	Warn     io.Writer
}

func (CertSpotter) Name() string { return "certspotter" }

type certspotterRow struct {
	ID       string   `json:"id"`
	DNSNames []string `json:"dns_names"`
	Issuer   *struct {
		Name string `json:"name"`
	} `json:"issuer"`
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`
}

var linkNext = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

// nextCursor pulls only the `after` cursor out of the rel="next" link. The link
// itself is not trusted: Cert Spotter sends /issuances without the /v1 prefix,
// and that path returns 404.
func nextCursor(link string) string {
	m := linkNext.FindStringSubmatch(link)
	if m == nil {
		return ""
	}
	u, err := url.Parse(m[1])
	if err != nil {
		return ""
	}
	return u.Query().Get("after")
}

func (s CertSpotter) Search(ctx context.Context, domain string, subdomains, includeExpired bool) ([]Certificate, error) {
	if includeExpired {
		warnf(s.Warn, "certspotter does not return expired certificates, use -source crtsh for full history")
	}
	base := s.BaseURL
	if base == "" {
		base = "https://api.certspotter.com/v1/issuances"
	}
	maxPages := s.MaxPages
	if maxPages <= 0 {
		maxPages = 20
	}
	q := url.Values{
		"domain":             {domain},
		"include_subdomains": {strconv.FormatBool(subdomains)},
		"expand":             {"dns_names", "issuer"},
	}
	var header map[string]string
	if s.APIKey != "" {
		header = map[string]string{"Authorization": "Bearer " + s.APIKey}
	}

	var certs []Certificate
	for page := 0; page < maxPages; page++ {
		resp, err := s.Client.Get(ctx, base+"?"+q.Encode(), header)
		if err != nil {
			if page > 0 && ctx.Err() == nil {
				// Partial results beat none: page 1 alone is often enough for small domains.
				warnf(s.Warn, "certspotter: page %d failed, results are incomplete: %v", page+1, err)
				return certs, nil
			}
			return certs, fmt.Errorf("certspotter: %w", err)
		}
		var rows []certspotterRow
		if err := json.Unmarshal(resp.Body, &rows); err != nil {
			return certs, fmt.Errorf("certspotter: expected JSON, got %s", snippet(resp.Body))
		}
		for _, r := range rows {
			names := Scope(r.DNSNames, domain, subdomains)
			if len(names) == 0 {
				continue
			}
			nb, err1 := parseTime(r.NotBefore)
			na, err2 := parseTime(r.NotAfter)
			if err1 != nil || err2 != nil {
				continue
			}
			c := Certificate{ID: r.ID, Source: s.Name(), DNSNames: names, NotBefore: nb, NotAfter: na}
			if r.Issuer != nil {
				c.Issuer = r.Issuer.Name
			}
			certs = append(certs, c)
		}
		after := nextCursor(resp.Header.Get("Link"))
		if after == "" {
			return certs, nil
		}
		q.Set("after", after)
	}
	warnf(s.Warn, "certspotter: stopped after %d pages, results are incomplete", maxPages)
	return certs, nil
}

// Auto tries crt.sh first (one request, full history) and falls back to Cert Spotter.
type Auto struct {
	Primary, Fallback Searcher
	Warn              io.Writer
}

func (Auto) Name() string { return "auto" }

func (a Auto) Search(ctx context.Context, domain string, subdomains, includeExpired bool) ([]Certificate, error) {
	certs, err := a.Primary.Search(ctx, domain, subdomains, includeExpired)
	if err == nil || ctx.Err() != nil {
		return certs, err
	}
	warnf(a.Warn, "%v; falling back to %s", err, a.Fallback.Name())
	return a.Fallback.Search(ctx, domain, subdomains, includeExpired)
}
