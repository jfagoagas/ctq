package ct

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
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
	primary := &fakeSearcher{name: "crtsh", err: fmt.Errorf("503")}
	fallback := &fakeSearcher{name: "certspotter", certs: []Certificate{{ID: "x"}}}
	var warn strings.Builder

	certs, err := Auto{Primary: primary, Fallback: fallback, Warn: &warn}.Search(context.Background(), "example.com", true, false)
	if err != nil || len(certs) != 1 || fallback.calls != 1 {
		t.Fatalf("certs=%v err=%v", certs, err)
	}
	if !strings.Contains(warn.String(), "falling back to certspotter") {
		t.Errorf("warning = %q", warn.String())
	}

	primary.err = nil
	fallback.calls = 0
	Auto{Primary: primary, Fallback: fallback}.Search(context.Background(), "example.com", true, false)
	if fallback.calls != 0 {
		t.Error("fallback called although primary succeeded")
	}
}
