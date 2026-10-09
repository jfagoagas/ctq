package main

// End-to-end tests for the search and watch commands. They go through run(), so
// flag parsing, output formats, stdout/stderr split and exit codes are all covered,
// with the real ct sources pointed at httptest fakes instead of the network.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jfagoagas/ctq/internal/ct"
)

// syncBuffer is a bytes.Buffer safe for the watcher's concurrent writes.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func runCLI(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut syncBuffer
	code = run(context.Background(), args, &out, &errOut)
	return code, out.String(), errOut.String()
}

// stubSearcher replaces the searcher factory for one test and records what runSearch asked for.
func stubSearcher(t *testing.T, build func(warn io.Writer) ct.Searcher) *searcherCall {
	t.Helper()
	call := &searcherCall{}
	orig := searcherFor
	t.Cleanup(func() { searcherFor = orig })
	searcherFor = func(source string, timeout time.Duration, warn io.Writer) (ct.Searcher, error) {
		call.source, call.timeout = source, timeout
		return build(warn), nil
	}
	return call
}

type searcherCall struct {
	source  string
	timeout time.Duration
}

func ctTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05") }

// fakeCrtSh serves crt.sh JSON rows and records each query string.
func fakeCrtSh(t *testing.T, rows []map[string]any) (*httptest.Server, *[]url.Values) {
	t.Helper()
	var mu sync.Mutex
	var queries []url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		queries = append(queries, r.URL.Query())
		mu.Unlock()
		json.NewEncoder(w).Encode(rows)
	}))
	t.Cleanup(srv.Close)
	return srv, &queries
}

var (
	now        = time.Now()
	recentNB   = now.Add(-24 * time.Hour)
	olderNB    = now.Add(-400 * 24 * time.Hour)
	searchRows = []map[string]any{
		{"id": 1, "issuer_name": "C=US, O=Let's Encrypt, CN=R11", "common_name": "www.example.com",
			"name_value": "www.example.com\napi.example.com", "not_before": ctTime(recentNB), "not_after": ctTime(now.Add(60 * 24 * time.Hour))},
		{"id": 2, "issuer_name": "C=US, O=Other, CN=Other CA", "common_name": "old.example.com",
			"name_value": "old.example.com\nwww.example.com", "not_before": ctTime(olderNB), "not_after": ctTime(olderNB.Add(90 * 24 * time.Hour))},
		// Out of scope: crt.sh can return these and the source must drop them.
		{"id": 3, "issuer_name": "CN=R11", "common_name": "unrelated.org",
			"name_value": "unrelated.org", "not_before": ctTime(recentNB), "not_after": ctTime(now.Add(time.Hour))},
	}
)

func crtshSearcher(srv *httptest.Server) func(io.Writer) ct.Searcher {
	return func(io.Writer) ct.Searcher {
		return ct.CrtSh{Client: ct.NewClient(5*time.Second, 0), BaseURL: srv.URL + "/"}
	}
}

func TestSearchNamesDefault(t *testing.T) {
	srv, queries := fakeCrtSh(t, searchRows)
	call := stubSearcher(t, crtshSearcher(srv))

	code, stdout, stderr := runCLI(t, "search", "-source", "crtsh", "-timeout", "7s", "Example.COM")
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	if want := "api.example.com\nold.example.com\nwww.example.com\n"; stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
	if stderr != "" {
		t.Errorf("stderr = %q, want nothing without -v or warnings", stderr)
	}
	if call.source != "crtsh" || call.timeout != 7*time.Second {
		t.Errorf("factory got source %q timeout %s", call.source, call.timeout)
	}
	q := (*queries)[0]
	if q.Get("q") != "%.example.com" || q.Get("exclude") != "expired" {
		t.Errorf("crt.sh query = %v, want subdomains of the normalized domain, expired excluded", q)
	}
}

func TestSearchFlags(t *testing.T) {
	for _, tc := range []struct {
		name, wantQ, wantExclude, wantOut string
		args                              []string
	}{
		{"exact", "example.com", "expired", "", []string{"-exact"}},
		{"expired", "%.example.com", "", "api.example.com\nold.example.com\nwww.example.com\n", []string{"-expired"}},
		{"issuer", "%.example.com", "expired", "old.example.com\nwww.example.com\n", []string{"-issuer", "other ca"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, queries := fakeCrtSh(t, searchRows)
			stubSearcher(t, crtshSearcher(srv))

			code, stdout, stderr := runCLI(t, append(append([]string{"search"}, tc.args...), "example.com")...)
			if code != 0 {
				t.Fatalf("exit %d, stderr %q", code, stderr)
			}
			q := (*queries)[0]
			if q.Get("q") != tc.wantQ || q.Get("exclude") != tc.wantExclude {
				t.Errorf("crt.sh query = %v, want q=%q exclude=%q", q, tc.wantQ, tc.wantExclude)
			}
			// -exact drops every row here: none lists the bare domain.
			if stdout != tc.wantOut {
				t.Errorf("stdout = %q, want %q", stdout, tc.wantOut)
			}
		})
	}
}

func TestSearchTable(t *testing.T) {
	srv, _ := fakeCrtSh(t, searchRows)
	stubSearcher(t, crtshSearcher(srv))

	code, stdout, stderr := runCLI(t, "search", "-o", "table", "example.com")
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	lines := strings.Split(strings.TrimRight(stdout, "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("want header + 2 rows, got %q", stdout)
	}
	if f := strings.Fields(lines[0]); strings.Join(f, " ") != "NOT BEFORE NOT AFTER STATUS ISSUER NAMES" {
		t.Errorf("header = %q", lines[0])
	}
	// Newest first, issuer reduced to its CN, status computed against now.
	want := [][]string{
		{recentNB.UTC().Format("2006-01-02"), "valid", "R11", "api.example.com,www.example.com"},
		{olderNB.UTC().Format("2006-01-02"), "expired", "Other CA", "old.example.com,www.example.com"},
	}
	for i, w := range want {
		row := lines[i+1]
		if !strings.HasPrefix(row, w[0]) {
			t.Errorf("row %d = %q, want it to start with %s", i, row, w[0])
		}
		for _, s := range w[1:] {
			if !strings.Contains(row, s) {
				t.Errorf("row %d = %q, missing %q", i, row, s)
			}
		}
	}
}

func TestSearchJSON(t *testing.T) {
	srv, _ := fakeCrtSh(t, searchRows)
	stubSearcher(t, crtshSearcher(srv))

	code, stdout, stderr := runCLI(t, "search", "-o", "json", "example.com")
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	var rows []struct {
		ID       string   `json:"id"`
		Source   string   `json:"source"`
		Issuer   string   `json:"issuer"`
		DNSNames []string `json:"dns_names"`
		Expired  bool     `json:"expired"`
	}
	if err := json.Unmarshal([]byte(stdout), &rows); err != nil {
		t.Fatalf("stdout is not a JSON array: %v\n%s", err, stdout)
	}
	if len(rows) != 2 || rows[0].ID != "1" || rows[1].ID != "2" {
		t.Fatalf("rows = %+v, want ids 1 then 2 (newest first)", rows)
	}
	if rows[0].Expired || !rows[1].Expired {
		t.Errorf("expired flags = %v, %v", rows[0].Expired, rows[1].Expired)
	}
	if rows[0].Source != "crtsh" || rows[0].Issuer != "C=US, O=Let's Encrypt, CN=R11" {
		t.Errorf("row 0 = %+v, want source crtsh and the full issuer DN", rows[0])
	}
}

func TestSearchEmptyResults(t *testing.T) {
	for format, want := range map[string]string{"names": "", "table": "NOT BEFORE  NOT AFTER  STATUS  ISSUER  NAMES\n", "json": "[]\n"} {
		t.Run(format, func(t *testing.T) {
			srv, _ := fakeCrtSh(t, []map[string]any{})
			stubSearcher(t, crtshSearcher(srv))

			code, stdout, stderr := runCLI(t, "search", "-o", format, "example.com")
			if code != 0 {
				t.Errorf("exit %d, want 0: no results is not an error (stderr %q)", code, stderr)
			}
			if stdout != want {
				t.Errorf("stdout = %q, want %q", stdout, want)
			}
		})
	}
}

func TestSearchVerboseTracesToStderr(t *testing.T) {
	srv, _ := fakeCrtSh(t, searchRows)
	stubSearcher(t, crtshSearcher(srv))

	code, stdout, stderr := runCLI(t, "search", "-v", "example.com")
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	if stdout != "api.example.com\nold.example.com\nwww.example.com\n" {
		t.Errorf("stdout = %q, the trace must not leak into it", stdout)
	}
	for _, want := range []string{"crtsh", "GET " + srv.URL, "HTTP 200", "3 rows"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr trace missing %q:\n%s", want, stderr)
		}
	}
}

func TestSearchFallbackWarnsOnStderr(t *testing.T) {
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "<html>timeout</html>", http.StatusServiceUnavailable)
	}))
	defer down.Close()
	spotter := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("domain") != "example.com" {
			t.Errorf("certspotter query = %v", r.URL.Query())
		}
		json.NewEncoder(w).Encode([]map[string]any{{
			"id": "abc", "dns_names": []string{"spot.example.com"}, "issuer": map[string]string{"name": "CN=R11"},
			"not_before": recentNB.UTC().Format(time.RFC3339), "not_after": now.Add(time.Hour).UTC().Format(time.RFC3339),
		}})
	}))
	defer spotter.Close()
	stubSearcher(t, func(warn io.Writer) ct.Searcher {
		return ct.Auto{Warn: warn, Sources: []ct.Searcher{
			ct.CrtSh{Client: ct.NewClient(5*time.Second, 0), BaseURL: down.URL + "/"},
			ct.CertSpotter{Client: ct.NewClient(5*time.Second, 0), BaseURL: spotter.URL, Warn: warn},
		}}
	})

	code, stdout, stderr := runCLI(t, "search", "example.com")
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	if stdout != "spot.example.com\n" {
		t.Errorf("stdout = %q, want only data", stdout)
	}
	if !strings.HasPrefix(stderr, "ctq: ") || !strings.Contains(stderr, "falling back to certspotter") {
		t.Errorf("stderr = %q, want the fallback warning", stderr)
	}
}

func TestExitCodes(t *testing.T) {
	notFound := httptest.NewServer(http.NotFoundHandler())
	defer notFound.Close()
	ok, _ := fakeCrtSh(t, searchRows)
	// Usage errors must fail before any network work; reaching the log list is a bug.
	stubLogs(t, nil, errors.New("log list fetched"))

	for _, tc := range []struct {
		name      string
		args      []string
		upstream  *httptest.Server // crt.sh fake; nil keeps the real factory
		code      int
		wantInErr string
	}{
		{"no command", nil, nil, 2, "Usage:"},
		{"unknown command", []string{"serach"}, nil, 2, `unknown command "serach"`},
		{"help", []string{"help"}, nil, 0, ""},
		{"version", []string{"version"}, nil, 0, ""},
		{"search without domain", []string{"search"}, nil, 2, "expected exactly one domain"},
		{"search two domains", []string{"search", "a.com", "b.com"}, nil, 2, "expected exactly one domain"},
		{"search invalid domain", []string{"search", "exa%mple.com"}, nil, 2, "invalid domain"},
		{"search unknown flag", []string{"search", "-nope", "example.com"}, nil, 2, "flag provided but not defined"},
		{"search bad flag value", []string{"search", "-timeout", "soon", "example.com"}, nil, 2, "invalid value"},
		{"search unknown source", []string{"search", "-source", "bogus", "example.com"}, nil, 2, `unknown source "bogus"`},
		{"search unknown output", []string{"search", "-o", "xml", "example.com"}, ok, 2, `unknown output "xml"`},
		{"search upstream error", []string{"search", "example.com"}, notFound, 1, "HTTP 404"},
		{"watch without domain", []string{"watch"}, nil, 2, "expected exactly one domain"},
		{"watch unknown flag", []string{"watch", "-nope", "example.com"}, nil, 2, "flag provided but not defined"},
		{"watch zero interval", []string{"watch", "-interval", "0", "example.com"}, nil, 2, "-interval must be positive"},
		{"watch negative interval", []string{"watch", "-interval", "-1s", "example.com"}, nil, 2, "-interval must be positive"},
		{"watch zero workers", []string{"watch", "-workers", "0", "example.com"}, nil, 2, "-workers must be positive"},
		{"tui two domains", []string{"tui", "a.com", "b.com"}, nil, 2, "expected at most one domain"},
		{"tui invalid domain", []string{"tui", "exa%mple.com"}, nil, 2, "invalid domain"},
		{"tui unknown flag", []string{"tui", "-nope"}, nil, 2, "flag provided but not defined"},
		{"tui unknown source", []string{"tui", "-source", "bogus"}, nil, 2, `unknown source "bogus"`},
		{"tui zero interval", []string{"tui", "-interval", "0"}, nil, 2, "-interval must be positive"},
		{"tui negative workers", []string{"tui", "-workers", "-1"}, nil, 2, "-workers must be positive"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.upstream != nil {
				stubSearcher(t, crtshSearcher(tc.upstream))
			}
			code, stdout, stderr := runCLI(t, tc.args...)
			if code != tc.code {
				t.Errorf("exit %d, want %d (stderr %q)", code, tc.code, stderr)
			}
			if tc.code != 0 && stdout != "" {
				t.Errorf("stdout = %q, want nothing on failure", stdout)
			}
			if !strings.Contains(stderr, tc.wantInErr) {
				t.Errorf("stderr = %q, want it to contain %q", stderr, tc.wantInErr)
			}
		})
	}
}

func TestSubcommandHelp(t *testing.T) {
	for cmd, synopsis := range map[string]string{
		"search": "Usage: ctq search [flags] <domain>",
		"watch":  "Usage: ctq watch [flags] <domain>",
		"tui":    "Usage: ctq tui [flags] [domain]",
	} {
		for _, flag := range []string{"-h", "--help"} {
			t.Run(cmd+flag, func(t *testing.T) {
				code, stdout, stderr := runCLI(t, cmd, flag)
				if code != 0 {
					t.Errorf("exit %d, want 0 (stderr %q)", code, stderr)
				}
				if !strings.HasPrefix(stdout, synopsis+"\n") || !strings.Contains(stdout, "-exact") {
					t.Errorf("stdout = %q, want the usage starting with %q and the flags", stdout, synopsis)
				}
				if stderr != "" {
					t.Errorf("stderr = %q, want nothing for a requested help", stderr)
				}
			})
		}
	}
}

// A bad -o must fail before the search, not after a minute in crt.sh's queue.
func TestSearchBadOutputSkipsSearch(t *testing.T) {
	call := stubSearcher(t, func(io.Writer) ct.Searcher {
		t.Error("searcher built for an invalid -o")
		return ct.Auto{} // no sources: returns nothing, without the network
	})
	code, stdout, stderr := runCLI(t, "search", "-o", "xml", "example.com")
	if code != 2 || stdout != "" || !strings.Contains(stderr, `ctq: unknown output "xml"`) {
		t.Errorf("exit %d stdout %q stderr %q, want exit 2 and the error", code, stdout, stderr)
	}
	if call.source != "" {
		t.Errorf("searcher factory called with source %q", call.source)
	}
}

// blockingSearcher returns only when its context is done, like a search Ctrl-C interrupts.
type blockingSearcher struct{}

func (blockingSearcher) Name() string { return "blocking" }

func (blockingSearcher) Search(ctx context.Context, _ string, _, _ bool) ([]ct.Certificate, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// Ctrl-C during a search exits 130, so `ctq search x > f && next` stops there.
func TestSearchInterruptedExits130(t *testing.T) {
	stubSearcher(t, func(io.Writer) ct.Searcher { return blockingSearcher{} })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out, errOut syncBuffer
	if code := run(ctx, []string{"search", "example.com"}, &out, &errOut); code != 130 {
		t.Errorf("exit %d, want 130 (stderr %q)", code, errOut.String())
	}
	if out.String() != "" || errOut.String() != "" {
		t.Errorf("stdout %q stderr %q, want nothing", out.String(), errOut.String())
	}
}

func TestSearchNamesStdoutBroken(t *testing.T) {
	srv, _ := fakeCrtSh(t, searchRows)
	stubSearcher(t, crtshSearcher(srv))
	var errOut syncBuffer
	code := run(context.Background(), []string{"search", "example.com"}, brokenWriter{}, &errOut)
	if code != 1 || !strings.Contains(errOut.String(), "ctq: broken pipe") {
		t.Errorf("exit %d stderr %q, want exit 1 and the write error", code, errOut.String())
	}
}

// --- watch ---

func makeCert(t *testing.T, names ...string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test CA"}, // self-signed: this is also the issuer
		DNSNames:     names,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// x509Leaf builds an RFC 6962 MerkleTreeLeaf holding an X509 entry.
func x509Leaf(der []byte) []byte {
	b := []byte{0, 0}                 // version v1, leaf type timestamped_entry
	b = append(b, make([]byte, 8)...) // timestamp
	b = append(b, 0, 0)               // entry type x509_entry
	b = append(b, byte(len(der)>>16), byte(len(der)>>8), byte(len(der)))
	b = append(b, der...)
	return append(b, 0, 0) // no extensions
}

// fakeRFC6962Log serves get-sth and get-entries for a fixed list of certificates.
func fakeRFC6962Log(t *testing.T, ders ...[]byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ct/v1/get-sth":
			json.NewEncoder(w).Encode(map[string]any{"tree_size": len(ders)})
		case "/ct/v1/get-entries":
			start, err1 := strconv.Atoi(r.URL.Query().Get("start"))
			end, err2 := strconv.Atoi(r.URL.Query().Get("end"))
			if err1 != nil || err2 != nil {
				http.Error(w, "bad range", http.StatusBadRequest)
				return
			}
			type entry struct {
				LeafInput []byte `json:"leaf_input"`
				ExtraData []byte `json:"extra_data"`
			}
			var entries []entry
			for i := start; i <= end && i < len(ders); i++ {
				entries = append(entries, entry{LeafInput: x509Leaf(ders[i]), ExtraData: []byte{}})
			}
			json.NewEncoder(w).Encode(map[string]any{"entries": entries})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func stubLogs(t *testing.T, logs []ct.Log, err error) {
	t.Helper()
	orig := fetchLogs
	t.Cleanup(func() { fetchLogs = orig })
	fetchLogs = func(context.Context, *ct.Client, time.Time) ([]ct.Log, error) {
		return append([]ct.Log(nil), logs...), err
	}
}

// startWatch runs `ctq watch` until stdout has want lines, then stops it the way Ctrl-C does.
func startWatch(t *testing.T, wantLines int, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out, errOut syncBuffer
	done := make(chan int, 1)
	go func() { done <- run(ctx, append([]string{"watch"}, args...), &out, &errOut) }()

	deadline := time.After(10 * time.Second)
	for strings.Count(out.String(), "\n") < wantLines {
		select {
		case code := <-done:
			return code, out.String(), errOut.String()
		case <-deadline:
			cancel()
			<-done
			t.Fatalf("timed out waiting for %d lines; stdout %q stderr %q", wantLines, out.String(), errOut.String())
		case <-time.After(10 * time.Millisecond):
		}
	}
	cancel()
	return <-done, out.String(), errOut.String()
}

// watchSetup serves one in-scope and one out-of-scope cert and seeds state at 0,
// since a fresh watch starts at the log's current size and would see nothing.
func watchSetup(t *testing.T) (statePath string) {
	t.Helper()
	log := fakeRFC6962Log(t, makeCert(t, "www.example.com", "other.net"), makeCert(t, "unrelated.org"))
	// The second log is unreachable: the -log filter must keep it out of the run.
	stubLogs(t, []ct.Log{{Name: "Test Log", URL: log.URL}, {Name: "Dead Log", URL: "http://127.0.0.1:1"}}, nil)
	statePath = filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(statePath, []byte(`{"`+log.URL+`": 0}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return statePath
}

func TestWatchText(t *testing.T) {
	statePath := watchSetup(t)

	code, stdout, stderr := startWatch(t, 1, "-state", statePath, "-log", "TEST", "-interval", "20ms", "example.com")
	if code != 0 {
		t.Fatalf("exit %d after Ctrl-C, want 0 (stderr %q)", code, stderr)
	}
	lines := strings.Split(strings.TrimRight(stdout, "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("stdout = %q, want one match", stdout)
	}
	// Kind and issuer CN, then only the in-scope SANs (other.net is dropped), then the log.
	if !strings.Contains(lines[0], "  cert     Test CA ") || !strings.HasSuffix(lines[0], "  www.example.com  [Test Log]") {
		t.Errorf("line = %q", lines[0])
	}
	if _, err := time.Parse(time.RFC3339, strings.Fields(lines[0])[0]); err != nil {
		t.Errorf("line does not start with an RFC 3339 time: %q", lines[0])
	}
	if !strings.Contains(stderr, "ctq: watching 1 logs (0 tiled) for example.com") {
		t.Errorf("stderr = %q, want the banner there and not on stdout", stderr)
	}

	// Ctrl-C saves offsets, so a restart resumes after the last entry read.
	var state map[string]uint64
	b, _ := os.ReadFile(statePath)
	if err := json.Unmarshal(b, &state); err != nil {
		t.Fatal(err)
	}
	for _, next := range state {
		if next != 2 {
			t.Errorf("saved state = %s, want offset 2", b)
		}
	}
}

func TestWatchJSON(t *testing.T) {
	statePath := watchSetup(t)

	code, stdout, stderr := startWatch(t, 1, "-json", "-state", statePath, "-log", "test", "-interval", "20ms", "example.com")
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	var m ct.Match
	if err := json.Unmarshal([]byte(strings.Split(stdout, "\n")[0]), &m); err != nil {
		t.Fatalf("stdout is not JSON lines: %v\n%s", err, stdout)
	}
	if m.Log != "Test Log" || m.Index != 0 || m.Precert || strings.Join(m.DNSNames, ",") != "www.example.com" {
		t.Errorf("match = %+v", m)
	}
	if strings.Contains(stdout, "watching") {
		t.Errorf("banner leaked to stdout: %q", stdout)
	}
}

type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

// A stdout that fails writes (ENOSPC or EIO on a redirected file, as in
// ctq watch -json > /full/disk/out) must end the watch with exit 1, not leave it
// tailing logs with nowhere to write. A closed pipe (ctq watch -json | head -1)
// never gets that far: the Go runtime exits with SIGPIPE on a write to fd 1.
func TestWatchJSONStdoutBroken(t *testing.T) {
	statePath := watchSetup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var errOut syncBuffer
	code := run(ctx, []string{"watch", "-json", "-state", statePath, "-log", "test", "-interval", "20ms", "example.com"},
		brokenWriter{}, &errOut)
	if code != 1 || !strings.Contains(errOut.String(), "ctq: writing JSON to stdout: broken pipe") {
		t.Errorf("exit %d stderr %q, want exit 1 and the write error", code, errOut.String())
	}
	if ctx.Err() != nil {
		t.Error("the watch ran until the test timeout instead of stopping on the write error")
	}
}

func TestWatchTextStdoutBroken(t *testing.T) {
	statePath := watchSetup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var errOut syncBuffer
	code := run(ctx, []string{"watch", "-state", statePath, "-log", "test", "-interval", "20ms", "example.com"},
		brokenWriter{}, &errOut)
	if code != 1 || !strings.Contains(errOut.String(), "ctq: writing to stdout: broken pipe") {
		t.Errorf("exit %d stderr %q, want exit 1 and the write error", code, errOut.String())
	}
	if ctx.Err() != nil {
		t.Error("the watch ran until the test timeout instead of stopping on the write error")
	}
}

func TestWatchErrors(t *testing.T) {
	t.Run("log list unreachable", func(t *testing.T) {
		stubLogs(t, nil, errors.New("giving up after 4 attempts"))
		code, stdout, stderr := runCLI(t, "watch", "example.com")
		if code != 1 || stdout != "" || !strings.Contains(stderr, "ctq: giving up after 4 attempts") {
			t.Errorf("exit %d stdout %q stderr %q", code, stdout, stderr)
		}
	})
	t.Run("filter matches no log", func(t *testing.T) {
		stubLogs(t, []ct.Log{{Name: "Test Log", URL: "http://127.0.0.1:1"}}, nil)
		code, stdout, stderr := runCLI(t, "watch", "-log", "nope", "example.com")
		if code != 1 || stdout != "" || !strings.Contains(stderr, "ctq: no logs to watch") {
			t.Errorf("exit %d stdout %q stderr %q", code, stdout, stderr)
		}
	})
	t.Run("corrupt state", func(t *testing.T) {
		stubLogs(t, []ct.Log{{Name: "Test Log", URL: "http://127.0.0.1:1"}}, nil)
		path := filepath.Join(t.TempDir(), "state.json")
		os.WriteFile(path, []byte("{not json"), 0o600)
		code, _, stderr := runCLI(t, "watch", "-state", path, "example.com")
		if code != 1 || !strings.Contains(stderr, "state "+path) {
			t.Errorf("exit %d stderr %q", code, stderr)
		}
	})
}
