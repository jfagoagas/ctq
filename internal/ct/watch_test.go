package ct

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
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
	synctest.Test(t, func(t *testing.T) {
		testWatcherMatchesAndDedups(t, logs)
	})
}

func testWatcherMatchesAndDedups(t *testing.T, logs map[string]*fakeLog) {
	state, _ := LoadState("")
	state.Set("https://a", 0)
	state.Set("https://b", 0)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
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
	if err := w.Run(ctx); err != nil {
		t.Fatal(err)
	}

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
	// Certs are made outside the bubble, whose fake clock starts in 2000.
	log := &fakeLog{entries: entriesFor(makeCert(t, 1, "a.example.com")), cap: 10}
	synctest.Test(t, func(t *testing.T) { testWatcherStartsAtCurrentSize(t, log) })
}

func testWatcherStartsAtCurrentSize(t *testing.T, log *fakeLog) {
	state, _ := LoadState("")
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()

	called := false
	w := &Watcher{
		Logs: []Log{{Name: "A", URL: "u"}}, NewReader: func(Log) LogReader { return log },
		Domain: "example.com", Subdomains: true, Interval: 10 * time.Millisecond, Workers: 1,
		State: state, Emit: func(Match) { called = true },
	}
	if err := w.Run(ctx); err != nil {
		t.Fatal(err)
	}
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
	if fi, err := os.Stat(path); err != nil {
		t.Fatal(err)
	} else if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Errorf("state mode = %v, want 0600", fi.Mode().Perm())
	}
	os.WriteFile(path, []byte("{bad"), 0o600)
	if _, err := LoadState(path); err == nil {
		t.Fatal("corrupt state loaded")
	}
}

// blockingWriter parks the first write until release is closed.
type blockingWriter struct {
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func (b *blockingWriter) Write(p []byte) (int, error) {
	b.once.Do(func() {
		close(b.entered)
		<-b.release
	})
	return len(p), nil
}

func TestWatcherRunWaitsForCheckpointSave(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// Saving into a missing directory fails, so the tick's Save ends in a warning,
		// and the warning parks the checkpoint goroutine mid-Save.
		state, _ := LoadState(filepath.Join(t.TempDir(), "missing", "state.json"))
		warn := &blockingWriter{entered: make(chan struct{}), release: make(chan struct{})}
		ctx, cancel := context.WithCancel(t.Context())
		w := &Watcher{
			Logs: []Log{{Name: "A", URL: "u"}}, NewReader: func(Log) LogReader { return &fakeLog{cap: 1} },
			Domain: "example.com", Interval: time.Second, Workers: 1,
			State: state, Emit: func(Match) {}, Warn: warn,
		}
		ran := make(chan struct{})
		go func() {
			w.Run(ctx)
			close(ran)
		}()

		<-warn.entered
		cancel()
		synctest.Wait()
		select {
		case <-ran:
			t.Fatal("Run returned while a checkpoint save was still in flight")
		default:
		}
		close(warn.release)
		<-ran
	})
}

// cancellingLog cancels the watch from inside a fetch, like a domain switch mid-batch.
type cancellingLog struct {
	fakeLog
	cancel context.CancelFunc
}

func (c *cancellingLog) Fetch(ctx context.Context, start, end uint64) ([]Entry, error) {
	c.cancel()
	return c.fakeLog.Fetch(ctx, start, end)
}

func TestWatcherNoProgressAfterCancel(t *testing.T) {
	entries := entriesFor(makeCert(t, 1, "a.example.com"), makeCert(t, 2, "b.example.com"))
	synctest.Test(t, func(t *testing.T) {
		state, _ := LoadState("")
		state.Set("u", 0)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		log := &cancellingLog{fakeLog: fakeLog{entries: entries, cap: 10}, cancel: cancel}

		var progress []uint64
		w := &Watcher{
			Logs: []Log{{Name: "A", URL: "u"}}, NewReader: func(Log) LogReader { return log },
			Domain: "example.com", Subdomains: true, Interval: time.Second, Workers: 1,
			State: state, Emit: func(Match) {},
			Progress: func(_ Log, next, _ uint64) { progress = append(progress, next) },
		}
		if err := w.Run(ctx); err != nil {
			t.Fatal(err)
		}
		if len(progress) != 0 {
			t.Errorf("progress reported after cancel: %v", progress)
		}
		if n, _ := state.Get("u"); n != 2 {
			t.Errorf("offset = %d, want 2: the batch read before cancel still counts", n)
		}
	})
}

func TestWatcherRunRejectsBadConfig(t *testing.T) {
	valid := func() *Watcher {
		state, _ := LoadState("")
		return &Watcher{Interval: time.Second, Workers: 1, State: state, Emit: func(Match) {}}
	}
	for name, tc := range map[string]struct {
		mod  func(*Watcher)
		want string
	}{
		"zero interval":     {func(w *Watcher) { w.Interval = 0 }, "interval"},
		"negative interval": {func(w *Watcher) { w.Interval = -time.Second }, "interval"},
		"zero workers":      {func(w *Watcher) { w.Workers = 0 }, "workers"},
		"nil emit":          {func(w *Watcher) { w.Emit = nil }, "Emit"},
	} {
		t.Run(name, func(t *testing.T) {
			w := valid()
			tc.mod(w)
			err := w.Run(t.Context())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want one about %s", err, tc.want)
			}
		})
	}
}
