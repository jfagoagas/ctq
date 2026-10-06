package ct

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
)

func testClient(retries int) *Client {
	c := NewClient(5*time.Second, retries)
	c.Backoff = time.Millisecond
	return c
}

func TestClientRetries(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	resp, err := testClient(3).Get(context.Background(), srv.URL, nil)
	if err != nil || string(resp.Body) != "ok" || hits.Load() != 3 {
		t.Fatalf("resp=%v err=%v hits=%d", resp, err, hits.Load())
	}
}

func TestClientNoRetryOn404(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.NotFound(w, r)
	}))
	defer srv.Close()

	_, err := testClient(3).Get(context.Background(), srv.URL, nil)
	if !IsNotFound(err) || hits.Load() != 1 {
		t.Fatalf("err=%v hits=%d", err, hits.Load())
	}
}

func TestClientLongRetryAfterFailsFast(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Retry-After", "3600")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	start := time.Now()
	_, err := testClient(3).Get(context.Background(), srv.URL, nil)
	if err == nil || !strings.Contains(err.Error(), "rate limited") || hits.Load() != 1 || time.Since(start) > time.Second {
		t.Fatalf("err=%v hits=%d", err, hits.Load())
	}
}

func TestCrtSh(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("q") != "%.example.com" || q.Get("exclude") != "expired" || q.Get("deduplicate") != "Y" {
			t.Errorf("unexpected query %v", q)
		}
		fmt.Fprint(w, `[
			{"id":1,"issuer_name":"C=US, O=Let's Encrypt, CN=R12","common_name":"a.example.com",
			 "name_value":"a.example.com\nwww.unrelated.org","not_before":"2026-09-01T00:00:00","not_after":"2026-11-30T00:00:00"},
			{"id":2,"issuer_name":"x","common_name":"cdn.other.net","name_value":"cdn.other.net",
			 "not_before":"2026-09-01T00:00:00","not_after":"2026-11-30T00:00:00"}
		]`)
	}))
	defer srv.Close()

	certs, err := CrtSh{Client: testClient(0), BaseURL: srv.URL + "/"}.Search(context.Background(), "example.com", true, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 1 || len(certs[0].DNSNames) != 1 || certs[0].DNSNames[0] != "a.example.com" {
		t.Fatalf("got %+v", certs)
	}
	if certs[0].NotAfter != time.Date(2026, 11, 30, 0, 0, 0, 0, time.UTC) {
		t.Errorf("NotAfter = %v", certs[0].NotAfter)
	}
}

func TestCrtShHTMLErrorPage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html>query_wait_timeout</html>")
	}))
	defer srv.Close()

	_, err := CrtSh{Client: testClient(0), BaseURL: srv.URL + "/"}.Search(context.Background(), "example.com", true, false)
	if err == nil || !strings.Contains(err.Error(), "expected JSON") {
		t.Fatalf("err = %v", err)
	}
}

func TestCertSpotterPaginates(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/issuances" {
			// The real API 404s here. Its own Link header points at this path.
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer k" {
			t.Errorf("missing auth header")
		}
		if r.URL.Query().Get("domain") != "example.com" {
			t.Errorf("next page lost the query: %v", r.URL.Query())
		}
		row := `{"id":"%s","dns_names":["%s"],"issuer":{"name":"C=US, CN=R12"},"not_before":"2026-09-01T00:00:00Z","not_after":"2026-12-01T00:00:00Z"}`
		if r.URL.Query().Get("after") == "" {
			// Mirrors the live server: no /v1 prefix in the next link.
			w.Header().Set("Link", fmt.Sprintf(`<%s/issuances?after=1&domain=example.com>; rel="next"`, srv.URL))
			fmt.Fprintf(w, "["+row+"]", "1", "a.example.com")
			return
		}
		fmt.Fprintf(w, "["+row+"]", "2", "b.example.com")
	}))
	defer srv.Close()

	s := CertSpotter{Client: testClient(0), BaseURL: srv.URL + "/v1/issuances", APIKey: "k"}
	certs, err := s.Search(context.Background(), "example.com", true, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 2 || certs[1].DNSNames[0] != "b.example.com" || certs[0].Issuer != "C=US, CN=R12" {
		t.Fatalf("got %+v", certs)
	}
}

func TestCertSpotterKeepsPartialResults(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("after") != "" {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.Header().Set("Link", fmt.Sprintf(`<%s/issuances?after=1>; rel="next"`, srv.URL))
		fmt.Fprint(w, `[{"id":"1","dns_names":["a.example.com"],"not_before":"2026-09-01T00:00:00Z","not_after":"2026-12-01T00:00:00Z"}]`)
	}))
	defer srv.Close()

	var warn strings.Builder
	s := CertSpotter{Client: testClient(0), BaseURL: srv.URL + "/v1/issuances", Warn: &warn}
	certs, err := s.Search(context.Background(), "example.com", true, false)
	if err != nil || len(certs) != 1 {
		t.Fatalf("certs=%v err=%v", certs, err)
	}
	if !strings.Contains(warn.String(), "incomplete") {
		t.Errorf("warning = %q", warn.String())
	}
}

// pagedCertSpotter serves `pages` pages of one issuance each. A page numbered
// limitAt (1-based, 0 disables it) answers 429 with an hour-long Retry-After.
func pagedCertSpotter(t *testing.T, pages, limitAt int) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		page := 1
		if a := r.URL.Query().Get("after"); a != "" {
			fmt.Sscan(a, &page)
		}
		if page == limitAt {
			w.Header().Set("Retry-After", "3600")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		if page < pages {
			w.Header().Set("Link", fmt.Sprintf(`<%s/issuances?after=%d>; rel="next"`, srv.URL, page+1))
		}
		fmt.Fprintf(w, `[{"id":"%d","dns_names":["p%d.example.com"],"not_before":"2026-09-01T00:00:00Z","not_after":"2026-12-01T00:00:00Z"}]`, page, page)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func pageTraces(traces []string) int {
	n := 0
	for _, m := range traces {
		if strings.HasPrefix(m, "page ") {
			n++
		}
	}
	return n
}

func TestCertSpotterKeyedPaginatesPastDefaultCap(t *testing.T) {
	srv, hits := pagedCertSpotter(t, 25, 0)
	var traces []string
	ctx := WithTracer(context.Background(), func(_ string, _ Level, msg string) { traces = append(traces, msg) })
	var warn strings.Builder
	s := CertSpotter{Client: testClient(0), BaseURL: srv.URL + "/v1/issuances", APIKey: "k", MaxPages: CertSpotterKeyedMaxPages, Warn: &warn}
	certs, err := s.Search(ctx, "example.com", true, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 25 || hits.Load() != 25 {
		t.Fatalf("certs=%d hits=%d, want 25", len(certs), hits.Load())
	}
	if warn.Len() != 0 {
		t.Errorf("complete search warned: %q", warn.String())
	}
	if n := pageTraces(traces); n != 25 {
		t.Errorf("traced %d pages, want 25", n)
	}
}

func TestCertSpotterRateLimitMidPagination(t *testing.T) {
	srv, hits := pagedCertSpotter(t, 50, 23)
	var warn strings.Builder
	s := CertSpotter{Client: testClient(2), BaseURL: srv.URL + "/v1/issuances", APIKey: "k", MaxPages: CertSpotterKeyedMaxPages, Warn: &warn}
	certs, err := s.Search(context.Background(), "example.com", true, false)
	if err != nil {
		t.Fatal(err)
	}
	// The long Retry-After fails page 23 at once instead of retrying it.
	if len(certs) != 22 || hits.Load() != 23 {
		t.Fatalf("certs=%d hits=%d, want 22 certs from 23 requests", len(certs), hits.Load())
	}
	if !strings.Contains(warn.String(), "rate limited on page 23, results are incomplete") {
		t.Errorf("warning = %q", warn.String())
	}
}

func TestCertSpotterUnkeyedStopsAtDefaultCap(t *testing.T) {
	srv, hits := pagedCertSpotter(t, 25, 0)
	var warn strings.Builder
	s := CertSpotter{Client: testClient(0), BaseURL: srv.URL + "/v1/issuances", Warn: &warn}
	certs, err := s.Search(context.Background(), "example.com", true, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != CertSpotterMaxPages || hits.Load() != CertSpotterMaxPages {
		t.Fatalf("certs=%d hits=%d, want %d", len(certs), hits.Load(), CertSpotterMaxPages)
	}
	if !strings.Contains(warn.String(), "stopped after 20 pages") {
		t.Errorf("warning = %q", warn.String())
	}
}

type fakeSearcher struct {
	name  string
	certs []Certificate
	err   error
	calls int
}

func (f *fakeSearcher) Name() string { return f.name }
func (f *fakeSearcher) Search(context.Context, string, bool, bool) ([]Certificate, error) {
	f.calls++
	return f.certs, f.err
}

func TestAutoFallsBack(t *testing.T) {
	db := &fakeSearcher{name: "crtsh-db", err: fmt.Errorf("max_client_conn")}
	web := &fakeSearcher{name: "crtsh", err: fmt.Errorf("503")}
	spotter := &fakeSearcher{name: "certspotter", certs: []Certificate{{ID: "x"}}}
	var warn strings.Builder

	certs, err := Auto{Sources: []Searcher{db, web, spotter}, Warn: &warn}.Search(context.Background(), "example.com", true, false)
	if err != nil || len(certs) != 1 || web.calls != 1 || spotter.calls != 1 {
		t.Fatalf("certs=%v err=%v", certs, err)
	}
	for _, want := range []string{"max_client_conn; falling back to crtsh", "503; falling back to certspotter"} {
		if !strings.Contains(warn.String(), want) {
			t.Errorf("warning %q missing from %q", want, warn.String())
		}
	}

	db.err = nil
	web.calls, spotter.calls = 0, 0
	Auto{Sources: []Searcher{db, web, spotter}}.Search(context.Background(), "example.com", true, false)
	if web.calls != 0 || spotter.calls != 0 {
		t.Error("fallback called although the first source succeeded")
	}
}

// stubDB is CrtShDB with a canned error; Name, backend and overloaded are the real ones.
type stubDB struct {
	CrtShDB
	err error
}

func (s stubDB) Search(context.Context, string, bool, bool) ([]Certificate, error) { return nil, s.err }

func TestAutoSkipsCrtShAPIWhenDBOverloaded(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		fmt.Fprint(w, `[]`)
	}))
	defer srv.Close()
	newAuto := func(dbErr error, spotter Searcher, warn *strings.Builder) Auto {
		web := CrtSh{Client: testClient(0), BaseURL: srv.URL + "/"}
		return Auto{Sources: []Searcher{stubDB{err: dbErr}, web, spotter}, Warn: warn}
	}

	t.Run("server side", func(t *testing.T) {
		hits.Store(0)
		dbErr := searchFake(t, fakePostgres(t, &pgproto3.ErrorResponse{Severity: "FATAL", Code: "08P01", Message: "no more connections allowed (max_client_conn)"}, nil), 5*time.Second)
		spotter := &fakeSearcher{name: "certspotter", certs: []Certificate{{ID: "x"}}}
		var warn strings.Builder
		var traced []string
		ctx := WithTracer(context.Background(), func(source string, level Level, msg string) {
			if source == "auto" && level == LevelWarn {
				traced = append(traced, msg)
			}
		})

		certs, err := newAuto(dbErr, spotter, &warn).Search(ctx, "example.com", true, false)
		if err != nil || len(certs) != 1 || spotter.calls != 1 {
			t.Fatalf("certs=%v err=%v", certs, err)
		}
		if hits.Load() != 0 {
			t.Error("crt.sh API queried although crt.sh's database refused the client")
		}
		if len(traced) != 2 ||
			!strings.HasPrefix(traced[0], "skipping crtsh: crtsh-db failed on crt.sh's side (crt.sh refused the work: no more connections allowed (max_client_conn))") ||
			!strings.HasSuffix(traced[1], "; falling back to certspotter") {
			t.Errorf("trace = %q", traced)
		}
		if !strings.Contains(warn.String(), "skipping crtsh") {
			t.Errorf("warnings = %q", warn.String())
		}
	})

	t.Run("network level", func(t *testing.T) {
		hits.Store(0)
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		l.Close()
		dbErr := searchFake(t, l.Addr().String(), 5*time.Second) // refused, as with port 5432 blocked
		spotter := &fakeSearcher{name: "certspotter"}
		var warn strings.Builder

		if _, err := newAuto(dbErr, spotter, &warn).Search(context.Background(), "example.com", true, false); err != nil {
			t.Fatal(err)
		}
		if hits.Load() != 1 || spotter.calls != 0 {
			t.Errorf("crt.sh API hits = %d, certspotter calls = %d; want the API to answer", hits.Load(), spotter.calls)
		}
		if strings.Contains(warn.String(), "skipping") || !strings.Contains(warn.String(), "falling back to crtsh") {
			t.Errorf("warnings = %q", warn.String())
		}
	})
}

func TestAutoReturnsLastError(t *testing.T) {
	a := &fakeSearcher{name: "a", err: fmt.Errorf("first")}
	b := &fakeSearcher{name: "b", err: fmt.Errorf("last")}
	_, err := Auto{Sources: []Searcher{a, b}}.Search(context.Background(), "example.com", true, false)
	if err == nil || err.Error() != "last" {
		t.Fatalf("err = %v", err)
	}
}

func TestTraceTagsEachSource(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) == 1 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		fmt.Fprint(w, `[]`)
	}))
	defer srv.Close()

	type event struct {
		source string
		level  Level
		msg    string
	}
	var events []event
	ctx := WithTracer(context.Background(), func(source string, level Level, msg string) {
		events = append(events, event{source, level, msg})
	})
	failing := &fakeSearcher{name: "crtsh-db", err: fmt.Errorf("dial timeout")}
	web := CrtSh{Client: testClient(1), BaseURL: srv.URL + "/?token=secret&"}
	if _, err := (Auto{Sources: []Searcher{failing, web}}).Search(ctx, "example.com", true, false); err != nil {
		t.Fatal(err)
	}

	want := []event{
		{"auto", LevelInfo, "trying crtsh-db"},
		{"auto", LevelWarn, "dial timeout; falling back to crtsh"},
		{"auto", LevelInfo, "trying crtsh"},
		{"crtsh", LevelInfo, "GET " + srv.URL + "/ (attempt 1 of 2)"},
		{"crtsh", LevelWarn, "attempt 1 failed after"},
		{"crtsh", LevelInfo, "GET " + srv.URL + "/ (attempt 2 of 2)"},
		{"crtsh", LevelInfo, "HTTP 200, 2 bytes in"},
		{"crtsh", LevelInfo, "0 rows"},
	}
	if len(events) != len(want) {
		t.Fatalf("got %d events: %+v", len(events), events)
	}
	for i, w := range want {
		e := events[i]
		if e.source != w.source || e.level != w.level || !strings.HasPrefix(e.msg, w.msg) {
			t.Errorf("event %d = %+v, want prefix %+v", i, e, w)
		}
		if strings.Contains(e.msg, "secret") {
			t.Errorf("event %d leaks the query string: %q", i, e.msg)
		}
	}
}

func TestTraceWithoutTracerIsNoop(t *testing.T) {
	Trace(context.Background(), LevelError, "nobody listens") // must not panic
}
