// Package ct queries Certificate Transparency: aggregators (crt.sh, Cert Spotter) for
// history, and the CT logs themselves (RFC 6962 and static-ct-api) for new entries.
package ct

import (
	"crypto/x509"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Certificate is the backend-agnostic view of one logged certificate.
// DNSNames only holds names inside the queried scope.
type Certificate struct {
	ID        string    `json:"id"`
	Source    string    `json:"source"`
	Issuer    string    `json:"issuer"`
	DNSNames  []string  `json:"dns_names"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
}

func (c Certificate) Expired(now time.Time) bool { return c.NotAfter.Before(now) }

// NormalizeName lowercases and strips the trailing root dot.
func NormalizeName(n string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(n)), ".")
}

var domainRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$`)

// NormalizeDomain validates user input as a domain. It also blocks SQL LIKE
// metacharacters (%, _) from reaching crt.sh, which would turn them into wildcards.
func NormalizeDomain(s string) (string, error) {
	d := strings.TrimPrefix(NormalizeName(s), "*.")
	if !domainRe.MatchString(d) {
		return "", fmt.Errorf("invalid domain %q", strings.TrimSpace(s))
	}
	return d, nil
}

// Matches reports whether name is the domain itself or, with subdomains, any name under it.
// Wildcards count as their base: *.example.com is in scope for example.com.
func Matches(name, domain string, subdomains bool) bool {
	bare := strings.TrimPrefix(name, "*.")
	if bare == domain {
		return true
	}
	return subdomains && strings.HasSuffix(bare, "."+domain)
}

// Scope drops names outside the query and sanitizes the rest. Multi-domain certs
// (CDNs, SaaS) carry dozens of unrelated SANs, and every backend returns them.
func Scope(names []string, domain string, subdomains bool) []string {
	set := make(map[string]struct{}, len(names))
	for _, n := range names {
		if n = sanitize(NormalizeName(n)); n != "" && Matches(n, domain, subdomains) {
			set[n] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func fromX509(id, source string, c *x509.Certificate, domain string, subdomains bool) (Certificate, bool) {
	names := Scope(slices.Concat(c.DNSNames, []string{c.Subject.CommonName}), domain, subdomains)
	if len(names) == 0 {
		return Certificate{}, false
	}
	return Certificate{
		ID:        id,
		Source:    source,
		Issuer:    sanitize(c.Issuer.String()),
		DNSNames:  names,
		NotBefore: c.NotBefore.UTC(),
		NotAfter:  c.NotAfter.UTC(),
	}, true
}

// sanitize escapes invalid UTF-8 and runes that are not printable, so text from
// CT data can't drive the terminal. Go's IA5String check lets ESC and BEL through,
// DN formatting doesn't escape them, and the aggregators' JSON isn't checked at all.
func sanitize(s string) string {
	if !strings.ContainsFunc(s, func(r rune) bool { return r == utf8.RuneError || !unicode.IsPrint(r) }) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, `\x%02x`, s[i])
		case !unicode.IsPrint(r) && r <= 0xff:
			fmt.Fprintf(&b, `\x%02x`, r)
		case !unicode.IsPrint(r) && r <= 0xffff:
			fmt.Fprintf(&b, `\u%04x`, r)
		case !unicode.IsPrint(r):
			fmt.Fprintf(&b, `\U%08x`, r)
		default:
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	return b.String()
}

var cnRe = regexp.MustCompile(`CN=([^,]+)`)

// IssuerCN extracts the CN from a DN. crt.sh, Cert Spotter and Go all format DNs
// differently, but all of them contain "CN=...".
func IssuerCN(dn string) string {
	if m := cnRe.FindStringSubmatch(dn); m != nil {
		return strings.TrimSpace(m[1])
	}
	return dn
}

// parseTime accepts RFC 3339 (Cert Spotter) and zone-less timestamps (crt.sh, always UTC).
func parseTime(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC(), nil
	}
	return time.ParseInLocation("2006-01-02T15:04:05.999999999", s, time.UTC)
}
