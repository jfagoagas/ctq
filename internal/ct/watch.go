package ct

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// Match is a certificate in scope, seen in a specific log entry.
type Match struct {
	Log     string `json:"log"`
	Index   uint64 `json:"index"`
	Precert bool   `json:"precert"`
	Certificate
}

// Watcher tails CT logs and emits certificates for one domain.
//
// Without saved state it starts at each log's current size: CT logs have no domain
// index, so there is no way to search backwards. History is what `search` is for.
type Watcher struct {
	Logs       []Log
	NewReader  func(Log) LogReader
	Domain     string
	Subdomains bool
	Interval   time.Duration
	Workers    int // concurrent fetches per log
	State      *State
	Emit       func(Match)
	Progress   func(l Log, next, size uint64) // optional; called after each poll and batch
	Error      func(l Log, err error)         // optional; per-log failures go here instead of Warn
	Warn       io.Writer
	Verbose    bool

	emitMu      sync.Mutex
	seen        dedup
	parseErrors atomic.Uint64
}

func (w *Watcher) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	for _, l := range w.Logs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w.tail(ctx, l)
		}()
	}

	// Checkpoint offsets on every tick so a crash loses at most one interval.
	done := make(chan struct{})
	go func() {
		t := time.NewTicker(w.Interval)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				if err := w.State.Save(); err != nil {
					warnf(w.Warn, "saving state: %v", err)
				}
			}
		}
	}()

	wg.Wait()
	close(done)
	if n := w.parseErrors.Load(); n > 0 && w.Verbose {
		warnf(w.Warn, "%d entries could not be parsed", n)
	}
	return w.State.Save()
}

func (w *Watcher) tail(ctx context.Context, l Log) {
	r := w.NewReader(l)
	next, started := w.State.Get(l.URL)
	batch := uint64(256) // shrinks to the server's real cap after the first short response

	for {
		size, err := r.Size(ctx)
		switch {
		case err != nil:
			if ctx.Err() == nil {
				w.logError(l, err)
			}
		case !started:
			next, started = size, true
			w.State.Set(l.URL, next)
			w.debugf("%s: starting at %d", l.Name, next)
		case size > next:
			next, batch = w.catchUp(ctx, r, l, next, size, batch)
		}
		if err == nil {
			w.progress(l, next, size)
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(w.Interval):
		}
	}
}

type span struct{ start, end uint64 }

type spanResult struct {
	entries  []Entry
	end      uint64
	shortest uint64 // smallest short response seen, 0 if the server never truncated
	err      error
}

// catchUp reads [next, size) with up to Workers spans in flight and processes
// them in order, so the saved offset never skips an unread entry.
func (w *Watcher) catchUp(ctx context.Context, r LogReader, l Log, next, size, batch uint64) (uint64, uint64) {
	for next < size && ctx.Err() == nil {
		spans := w.plan(l, next, size, batch)
		results := make([]spanResult, len(spans))
		var wg sync.WaitGroup
		for i, sp := range spans {
			wg.Add(1)
			go func() {
				defer wg.Done()
				results[i] = fetchSpan(ctx, r, sp)
			}()
		}
		wg.Wait()

		for _, res := range results {
			if res.err != nil {
				if ctx.Err() == nil {
					w.logError(l, res.err)
				}
				w.State.Set(l.URL, next)
				return next, batch
			}
			if res.shortest > 0 && res.shortest < batch {
				batch = res.shortest
			}
			w.process(l, res.entries)
			next = res.end
		}
		w.State.Set(l.URL, next)
		w.progress(l, next, size)
		w.debugf("%s: at %d, lag %d", l.Name, next, size-next)
	}
	return next, batch
}

// logError reports a failed poll or fetch. The tail retries on the next poll either
// way: static-ct-api logs can publish a checkpoint before its tiles are readable.
func (w *Watcher) logError(l Log, err error) {
	if w.Error != nil {
		w.Error(l, err)
		return
	}
	warnf(w.Warn, "%s: %v", l.Name, err)
}

func (w *Watcher) progress(l Log, next, size uint64) {
	if w.Progress != nil {
		w.Progress(l, next, size)
	}
}

func (w *Watcher) plan(l Log, next, size, batch uint64) []span {
	var out []span
	for s := next; len(out) < max(w.Workers, 1) && s < size; {
		e := s + batch
		if l.Tiled {
			e = (s/TileWidth + 1) * TileWidth
		}
		e = min(e, size)
		out = append(out, span{s, e})
		s = e
	}
	return out
}

func fetchSpan(ctx context.Context, r LogReader, sp span) spanResult {
	res := spanResult{end: sp.end}
	for s := sp.start; s < sp.end; {
		es, err := r.Fetch(ctx, s, sp.end)
		if err != nil {
			res.err = err
			return res
		}
		if len(es) == 0 || es[0].Index != s {
			res.err = fmt.Errorf("fetch at %d returned misaligned entries", s)
			return res
		}
		n := uint64(len(es))
		if n < sp.end-s && (res.shortest == 0 || n < res.shortest) {
			res.shortest = n
		}
		res.entries = append(res.entries, es...)
		s += n
	}
	return res
}

func (w *Watcher) process(l Log, entries []Entry) {
	for _, e := range entries {
		if e.DER == nil {
			w.parseErrors.Add(1)
			continue
		}
		c, err := x509.ParseCertificate(e.DER)
		if err != nil {
			// Logs accept certs Go rejects (negative serials, broken encodings).
			w.parseErrors.Add(1)
			continue
		}
		cert, ok := fromX509(c.SerialNumber.Text(16), l.Name, c, w.Domain, w.Subdomains)
		if !ok {
			continue
		}
		// Every cert lands in 2+ logs, usually twice per log (precert, then final cert).
		// Issuer+serial is shared by all of those copies.
		if !w.seen.first(string(c.RawIssuer) + "/" + c.SerialNumber.String()) {
			continue
		}
		w.emitMu.Lock()
		w.Emit(Match{Log: l.Name, Index: e.Index, Precert: e.Precert, Certificate: cert})
		w.emitMu.Unlock()
	}
}

func (w *Watcher) debugf(format string, args ...any) {
	if w.Verbose {
		warnf(w.Warn, format, args...)
	}
}

type dedup struct {
	mu sync.Mutex
	m  map[string]struct{}
}

func (d *dedup) first(k string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	// Crude bound: a domain's cert copies arrive within minutes of each other.
	if d.m == nil || len(d.m) > 100_000 {
		d.m = make(map[string]struct{})
	}
	if _, ok := d.m[k]; ok {
		return false
	}
	d.m[k] = struct{}{}
	return true
}

// State holds the next unread index per log, persisted as JSON so `watch` can resume.
type State struct {
	mu   sync.Mutex
	path string
	next map[string]uint64
}

func LoadState(path string) (*State, error) {
	s := &State{path: path, next: map[string]uint64{}}
	if path == "" {
		return s, nil
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &s.next); err != nil {
		return nil, fmt.Errorf("state %s: %w", path, err)
	}
	return s, nil
}

func (s *State) Get(log string) (uint64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := s.next[log]
	return n, ok
}

func (s *State) Set(log string, next uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.next[log] = next
}

// Save writes atomically (temp file + rename) so a kill mid-write can't corrupt offsets.
func (s *State) Save() error {
	if s.path == "" {
		return nil
	}
	s.mu.Lock()
	b, err := json.MarshalIndent(s.next, "", "  ")
	s.mu.Unlock()
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".ctq-state-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), s.path)
}
