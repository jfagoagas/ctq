package ct

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// fakeLog serves a fixed set of entries and truncates batches like Argon does.
type fakeLog struct {
	entries []Entry
	cap     int
}

func (f *fakeLog) Size(context.Context) (uint64, error) { return uint64(len(f.entries)), nil }

func (f *fakeLog) Fetch(_ context.Context, start, end uint64) ([]Entry, error) {
	end = min(end, start+uint64(f.cap), uint64(len(f.entries)))
	return f.entries[start:end], nil
}

func entriesFor(ders ...[]byte) []Entry {
	out := make([]Entry, len(ders))
	for i, d := range ders {
		out[i] = Entry{Index: uint64(i), DER: d}
	}
	return out
}

func TestWatcherMatchesAndDedups(t *testing.T) {
	hit := makeCert(t, 1, "api.example.com", "cdn.other.net")
	miss := makeCert(t, 2, "unrelated.org")
	hit2 := makeCert(t, 3, "example.com")

	// The same cert in two logs must be reported once. One log caps batches at 2,
	// and a nil DER (unparseable entry) must not stall the tail.
	logs := map[string]*fakeLog{
		"https://a": {entries: entriesFor(miss, hit, miss, nil, hit2), cap: 2},
		"https://b": {entries: entriesFor(hit, miss), cap: 100},
	}
	state, _ := LoadState("")
	state.Set("https://a", 0)
	state.Set("https://b", 0)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var mu sync.Mutex
	var got []Match
	w := &Watcher{
		Logs:       []Log{{Name: "A", URL: "https://a"}, {Name: "B", URL: "https://b"}},
		NewReader:  func(l Log) LogReader { return logs[l.URL] },
		Domain:     "example.com",
		Subdomains: true,
		Interval:   10 * time.Millisecond,
		Workers:    3,
		State:      state,
		Emit: func(m Match) {
			mu.Lock()
			got = append(got, m)
			if len(got) == 2 {
				cancel()
			}
			mu.Unlock()
		},
	}
	w.Run(ctx)

	if len(got) != 2 {
		t.Fatalf("got %d matches: %+v", len(got), got)
	}
	names := map[string]bool{}
	for _, m := range got {
		names[m.DNSNames[0]] = true
		if len(m.DNSNames) != 1 {
			t.Errorf("out-of-scope SAN leaked: %v", m.DNSNames)
		}
	}
	if !names["api.example.com"] || !names["example.com"] {
		t.Errorf("matches = %v", names)
	}
	if n, _ := state.Get("https://a"); n != 5 {
		t.Errorf("log a offset = %d, want 5", n)
	}
	if w.parseErrors.Load() != 1 {
		t.Errorf("parse errors = %d, want 1", w.parseErrors.Load())
	}
}

func TestWatcherStartsAtCurrentSize(t *testing.T) {
	log := &fakeLog{entries: entriesFor(makeCert(t, 1, "a.example.com")), cap: 10}
	state, _ := LoadState("")
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	called := false
	w := &Watcher{
		Logs: []Log{{Name: "A", URL: "u"}}, NewReader: func(Log) LogReader { return log },
		Domain: "example.com", Subdomains: true, Interval: 10 * time.Millisecond, Workers: 1,
		State: state, Emit: func(Match) { called = true },
	}
	w.Run(ctx)
	if called {
		t.Error("emitted an entry that was already in the log at startup")
	}
	if n, ok := state.Get("u"); !ok || n != 1 {
		t.Errorf("offset = %d, %v", n, ok)
	}
}

func TestPlanTiledAlignsToTiles(t *testing.T) {
	w := &Watcher{Workers: 4}
	got := w.plan(Log{Tiled: true}, 300, 800, 0)
	want := []span{{300, 512}, {512, 768}, {768, 800}}
	if len(got) != len(want) {
		t.Fatalf("plan = %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("plan = %v, want %v", got, want)
		}
	}
}

func TestStateRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	s.Set("https://log", 42)
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	s2, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if n, ok := s2.Get("https://log"); !ok || n != 42 {
		t.Fatalf("got %d, %v", n, ok)
	}
	os.WriteFile(path, []byte("{bad"), 0o600)
	if _, err := LoadState(path); err == nil {
		t.Fatal("corrupt state loaded")
	}
}
