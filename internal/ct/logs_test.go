package ct

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestParseRFC6962Leaf(t *testing.T) {
	der := makeCert(t, 1, "a.example.com")

	e, err := ParseRFC6962Leaf(7, rfcX509Leaf(der), nil)
	if err != nil || e.Index != 7 || e.Precert || !bytes.Equal(e.DER, der) {
		t.Fatalf("x509 leaf: %+v, %v", e, err)
	}

	e, err = ParseRFC6962Leaf(8, rfcPrecertLeaf(), rfcPrecertExtra(der))
	if err != nil || !e.Precert || !bytes.Equal(e.DER, der) {
		t.Fatalf("precert leaf: %+v, %v", e, err)
	}

	if _, err := ParseRFC6962Leaf(0, rfcX509Leaf(der)[:20], nil); err == nil {
		t.Fatal("truncated leaf parsed")
	}
	if _, err := ParseRFC6962Leaf(0, cat([]byte{1, 0}, rfcX509Leaf(der)[2:]), nil); err == nil {
		t.Fatal("v2 leaf parsed")
	}
}

func TestParseTile(t *testing.T) {
	a, b := makeCert(t, 1, "a.example.com"), makeCert(t, 2, "b.example.com")
	entries, err := ParseTile(512, cat(tileX509(a), tilePrecert(b)))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries", len(entries))
	}
	if entries[0].Index != 512 || entries[0].Precert || !bytes.Equal(entries[0].DER, a) {
		t.Errorf("entry 0: %+v", entries[0])
	}
	if entries[1].Index != 513 || !entries[1].Precert || !bytes.Equal(entries[1].DER, b) {
		t.Errorf("entry 1: %+v", entries[1])
	}

	if _, err := ParseTile(0, tileX509(a)[:30]); err == nil {
		t.Fatal("truncated tile parsed")
	}
}

func TestTilePath(t *testing.T) {
	cases := []struct {
		n    uint64
		want string
	}{
		{0, "000"},
		{5, "005"},
		{999, "999"},
		{1000, "x001/000"},
		{1234067, "x001/x234/067"},
	}
	for _, c := range cases {
		t.Run(strconv.FormatUint(c.n, 10), func(t *testing.T) {
			if got := tilePath(c.n); got != c.want {
				t.Errorf("tilePath(%d) = %q, want %q", c.n, got, c.want)
			}
		})
	}
}

func TestParseLogList(t *testing.T) {
	now := time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)
	body := []byte(`{"operators":[{"name":"Op","logs":[
		{"description":"live","url":"https://a/","state":{"usable":{}},"temporal_interval":{"start_inclusive":"2026-07-01T00:00:00Z","end_exclusive":"2027-01-01T00:00:00Z"}},
		{"description":"retired","url":"https://b/","state":{"retired":{}}},
		{"description":"past shard","url":"https://c/","state":{"usable":{}},"temporal_interval":{"start_inclusive":"2026-01-01T00:00:00Z","end_exclusive":"2026-07-01T00:00:00Z"}}
	],"tiled_logs":[
		{"description":"tiled","submission_url":"https://d/","monitoring_url":"https://mon.d/2026h2/","state":{"qualified":{}}}
	]}]}`)
	logs, err := parseLogList(body, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) != 2 {
		t.Fatalf("got %+v", logs)
	}
	if logs[0].Name != "live" || logs[0].URL != "https://a" || logs[0].Tiled {
		t.Errorf("rfc log: %+v", logs[0])
	}
	if logs[1].URL != "https://mon.d/2026h2" || !logs[1].Tiled {
		t.Errorf("tiled log must use monitoring_url: %+v", logs[1])
	}
}

func TestMatchesAndScope(t *testing.T) {
	cases := []struct {
		name       string
		subdomains bool
		want       bool
	}{
		{"example.com", false, true},
		{"*.example.com", false, true},
		{"a.example.com", false, false},
		{"a.example.com", true, true},
		{"*.a.example.com", true, true},
		{"notexample.com", true, false},
		{"example.com.evil.net", true, false},
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("%s/sub=%v", c.name, c.subdomains), func(t *testing.T) {
			if got := Matches(c.name, "example.com", c.subdomains); got != c.want {
				t.Errorf("Matches(%q, sub=%v) = %v", c.name, c.subdomains, got)
			}
		})
	}
	got := Scope([]string{"B.Example.com.", "b.example.com", "cdn.other.net", "", "Acme Inc"}, "example.com", true)
	if len(got) != 1 || got[0] != "b.example.com" {
		t.Errorf("Scope = %v", got)
	}
}

func TestNormalizeDomain(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Example.COM.", "example.com"},
		{"*.example.com", "example.com"},
		{" sub.example.co.uk", "sub.example.co.uk"},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			if got, err := NormalizeDomain(c.in); err != nil || got != c.want {
				t.Errorf("NormalizeDomain(%q) = %q, %v", c.in, got, err)
			}
		})
	}
	// % and _ are SQL LIKE wildcards on crt.sh. They must never pass.
	for _, bad := range []string{"%.com", "ex_ample.com", "localhost", "", "a..com", "https://example.com"} {
		t.Run(fmt.Sprintf("reject %q", bad), func(t *testing.T) {
			if _, err := NormalizeDomain(bad); err == nil {
				t.Errorf("NormalizeDomain(%q) accepted", bad)
			}
		})
	}
}

func TestIssuerCN(t *testing.T) {
	cases := []struct{ in, want string }{
		{"C=US, O=Let's Encrypt, CN=R12", "R12"},
		{"CN=R10,O=Let's Encrypt,C=US", "R10"},
		{"O=No CN", "O=No CN"},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			if got := IssuerCN(c.in); got != c.want {
				t.Errorf("IssuerCN(%q) = %q", c.in, got)
			}
		})
	}
}

func TestParseCheckpoint(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		want    uint64
		wantErr error // nil means any error is fine, as long as one is expected
		fails   bool
	}{
		{name: "full note", body: string(checkpointBody(12345)), want: 12345},
		{name: "no root hash", body: "example.com/log\n7", want: 7},
		{name: "zero", body: "example.com/log\n0\n", want: 0},
		{name: "max", body: "o\n18446744073709551615\n", want: 18446744073709551615},
		{name: "empty", body: "", fails: true},
		{name: "origin only", body: "example.com/log", fails: true},
		{name: "not a number", body: "example.com/log\nabc\n", wantErr: strconv.ErrSyntax, fails: true},
		{name: "negative", body: "example.com/log\n-1\n", wantErr: strconv.ErrSyntax, fails: true},
		{name: "overflow", body: "example.com/log\n18446744073709551616\n", wantErr: strconv.ErrRange, fails: true},
		{name: "crlf", body: "example.com/log\r\n5\r\n", wantErr: strconv.ErrSyntax, fails: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parseCheckpoint([]byte(c.body))
			if !c.fails {
				if err != nil || got != c.want {
					t.Fatalf("parseCheckpoint = %d, %v; want %d", got, err, c.want)
				}
				return
			}
			if err == nil {
				t.Fatalf("parseCheckpoint = %d, want an error", got)
			}
			if !strings.HasPrefix(err.Error(), "checkpoint: ") {
				t.Errorf("error %q lacks the checkpoint: prefix", err)
			}
			if c.wantErr != nil && !errors.Is(err, c.wantErr) {
				t.Errorf("error %q does not wrap %v", err, c.wantErr)
			}
		})
	}
}

// tiledServer serves a static-ct-api log from a map of paths to bodies and records
// every path it is asked for.
func tiledServer(t *testing.T, files map[string][]byte) (*TiledLog, *[]string) {
	t.Helper()
	var mu sync.Mutex
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		body, ok := files[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return &TiledLog{Client: testClient(0), Base: srv.URL}, &paths
}

func TestTiledLogSize(t *testing.T) {
	l, _ := tiledServer(t, map[string][]byte{"/checkpoint": checkpointBody(300)})
	if size, err := l.Size(context.Background()); err != nil || size != 300 {
		t.Fatalf("Size = %d, %v", size, err)
	}

	l, _ = tiledServer(t, map[string][]byte{"/checkpoint": []byte("example.com/log\nnot-a-size\n")})
	if _, err := l.Size(context.Background()); err == nil || !strings.HasPrefix(err.Error(), "checkpoint: ") {
		t.Fatalf("malformed checkpoint: %v", err)
	}

	l, _ = tiledServer(t, nil)
	if _, err := l.Size(context.Background()); !IsNotFound(err) {
		t.Fatalf("missing checkpoint: %v", err)
	}
}

func TestTiledLogFetch(t *testing.T) {
	// A 300-entry log: one full tile (000) and a partial tile of 44 entries (001.p/44).
	files := map[string][]byte{
		"/tile/data/000":      dataTile(0, TileWidth),
		"/tile/data/001.p/44": dataTile(TileWidth, 44),
	}
	cases := []struct {
		name       string
		start, end uint64
		wantPath   string
		first, n   uint64
	}{
		{"full tile", 0, 256, "/tile/data/000", 0, 256},
		{"full tile, end past it", 0, 300, "/tile/data/000", 0, 256},
		{"partial tile", 256, 300, "/tile/data/001.p/44", 256, 44},
		{"middle of full tile", 100, 256, "/tile/data/000", 100, 156},
		{"middle of partial tile", 290, 300, "/tile/data/001.p/44", 290, 10},
		{"range spanning two tiles stops at the boundary", 200, 300, "/tile/data/000", 200, 56},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			l, paths := tiledServer(t, files)
			entries, err := l.Fetch(context.Background(), c.start, c.end)
			if err != nil {
				t.Fatal(err)
			}
			if len(*paths) != 1 || (*paths)[0] != c.wantPath {
				t.Errorf("requested %v, want [%s]", *paths, c.wantPath)
			}
			if uint64(len(entries)) != c.n {
				t.Fatalf("got %d entries, want %d", len(entries), c.n)
			}
			for k, e := range entries {
				if want := c.first + uint64(k); e.Index != want || e.Precert || !bytes.Equal(e.DER, fakeDER(want)) {
					t.Fatalf("entry %d: %+v, want index %d", k, e, want)
				}
			}
		})
	}

	t.Run("two tiles in sequence", func(t *testing.T) {
		l, paths := tiledServer(t, files)
		var got []Entry
		for next := uint64(200); next < 300; {
			entries, err := l.Fetch(context.Background(), next, 300)
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, entries...)
			next = entries[len(entries)-1].Index + 1
		}
		if want := []string{"/tile/data/000", "/tile/data/001.p/44"}; !slices.Equal(*paths, want) {
			t.Errorf("requested %v, want %v", *paths, want)
		}
		if len(got) != 100 || got[0].Index != 200 || got[99].Index != 299 {
			t.Fatalf("got %d entries, %+v .. %+v", len(got), got[0], got[len(got)-1])
		}
	})
}

func TestTiledLogFetchErrors(t *testing.T) {
	cases := []struct {
		name       string
		tile       []byte
		start, end uint64
		check      func(error) bool
	}{
		{"missing tile", nil, 0, 256, IsNotFound},
		{"truncated tile", dataTile(0, 3)[:30], 0, 256, func(err error) bool {
			return errors.Is(err, errTruncated)
		}},
		{"short tile has nothing at start", dataTile(0, 10), 100, 256, func(err error) bool {
			return strings.Contains(err.Error(), "no entries at or after 100")
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			files := map[string][]byte{}
			if c.tile != nil {
				files["/tile/data/000"] = c.tile
			}
			l, _ := tiledServer(t, files)
			entries, err := l.Fetch(context.Background(), c.start, c.end)
			if err == nil || !c.check(err) {
				t.Fatalf("Fetch = %d entries, %v", len(entries), err)
			}
		})
	}

	t.Run("server error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer srv.Close()
		l := &TiledLog{Client: testClient(1), Base: srv.URL}
		var herr *HTTPError
		if _, err := l.Fetch(context.Background(), 0, 256); !errors.As(err, &herr) || herr.Code != http.StatusInternalServerError {
			t.Fatalf("Fetch: %v", err)
		}
		if _, err := l.Size(context.Background()); !errors.As(err, &herr) || herr.Code != http.StatusInternalServerError {
			t.Fatalf("Size: %v", err)
		}
	})
}

type rfcEntry struct {
	LeafInput []byte `json:"leaf_input"`
	ExtraData []byte `json:"extra_data"`
}

// rfcServer serves get-entries with the given entries, whatever range is asked for,
// and records the raw query of each request.
func rfcServer(t *testing.T, entries []rfcEntry) (*RFC6962Log, *[]string) {
	t.Helper()
	body, err := json.Marshal(map[string]any{"entries": entries})
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var queries []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ct/v1/get-sth":
			_, _ = w.Write([]byte(`{"tree_size":1234,"timestamp":1}`))
		case "/ct/v1/get-entries":
			mu.Lock()
			queries = append(queries, r.URL.RawQuery)
			mu.Unlock()
			_, _ = w.Write(body)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return &RFC6962Log{Client: testClient(0), Base: srv.URL}, &queries
}

func TestRFC6962LogFetch(t *testing.T) {
	var five []rfcEntry
	for i := range uint64(5) {
		five = append(five, rfcEntry{LeafInput: rfcX509Leaf(fakeDER(10 + i))})
	}

	t.Run("size", func(t *testing.T) {
		l, _ := rfcServer(t, nil)
		if size, err := l.Size(context.Background()); err != nil || size != 1234 {
			t.Fatalf("Size = %d, %v", size, err)
		}
	})

	t.Run("exact batch", func(t *testing.T) {
		l, queries := rfcServer(t, five)
		entries, err := l.Fetch(context.Background(), 10, 15)
		if err != nil {
			t.Fatal(err)
		}
		if want := []string{"start=10&end=14"}; !slices.Equal(*queries, want) {
			t.Errorf("queries %v, want %v", *queries, want)
		}
		if len(entries) != 5 || entries[4].Index != 14 || !bytes.Equal(entries[4].DER, fakeDER(14)) {
			t.Fatalf("entries: %+v", entries)
		}
	})

	t.Run("server returns more than asked", func(t *testing.T) {
		l, _ := rfcServer(t, five)
		entries, err := l.Fetch(context.Background(), 10, 12)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 2 || entries[0].Index != 10 || entries[1].Index != 11 {
			t.Fatalf("want entries 10 and 11 only, got %+v", entries)
		}
	})

	t.Run("server caps the batch", func(t *testing.T) {
		l, _ := rfcServer(t, five[:2])
		entries, err := l.Fetch(context.Background(), 10, 15)
		if err != nil || len(entries) != 2 || entries[1].Index != 11 {
			t.Fatalf("entries %+v, %v", entries, err)
		}
	})

	t.Run("undecodable leaf keeps its slot", func(t *testing.T) {
		bad := slices.Clone(five[:3])
		bad[1] = rfcEntry{LeafInput: []byte{0, 0, 1}}
		l, _ := rfcServer(t, bad)
		entries, err := l.Fetch(context.Background(), 10, 13)
		if err != nil || len(entries) != 3 {
			t.Fatalf("entries %+v, %v", entries, err)
		}
		if entries[1].Index != 11 || entries[1].DER != nil || entries[2].Index != 12 || entries[2].DER == nil {
			t.Fatalf("entries %+v", entries)
		}
	})

	t.Run("no entries", func(t *testing.T) {
		l, _ := rfcServer(t, nil)
		entries, err := l.Fetch(context.Background(), 10, 15)
		if err == nil || !strings.Contains(err.Error(), "no entries for [10, 15)") {
			t.Fatalf("Fetch = %+v, %v", entries, err)
		}
	})
}

func TestRFC6962LogErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/bad-json/ct/v1/get-sth" || r.URL.Path == "/bad-json/ct/v1/get-entries" {
			_, _ = w.Write([]byte("{"))
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	bad := &RFC6962Log{Client: testClient(0), Base: srv.URL + "/bad-json"}
	if _, err := bad.Size(context.Background()); err == nil || !strings.HasPrefix(err.Error(), "get-sth: ") {
		t.Errorf("Size with bad JSON: %v", err)
	}
	if _, err := bad.Fetch(context.Background(), 0, 1); err == nil || !strings.HasPrefix(err.Error(), "get-entries: ") {
		t.Errorf("Fetch with bad JSON: %v", err)
	}

	l := &RFC6962Log{Client: testClient(0), Base: srv.URL}
	var herr *HTTPError
	if _, err := l.Size(context.Background()); !errors.As(err, &herr) || herr.Code != http.StatusBadRequest {
		t.Errorf("Size: %v", err)
	}
	if _, err := l.Fetch(context.Background(), 0, 1); !errors.As(err, &herr) || herr.Code != http.StatusBadRequest {
		t.Errorf("Fetch: %v", err)
	}
}
