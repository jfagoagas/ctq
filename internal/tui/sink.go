package tui

import (
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jfagoagas/ctq/internal/ct"
)

// A log is "retrying" after a failed poll and "failing" after failingAfter in a row.
// Tiled logs sometimes publish a checkpoint before its tiles are readable, so a
// single 404 is normal and fixes itself on the next poll.
const failingAfter = 3

type logStatus int

const (
	logOK logStatus = iota
	logCatchingUp
	logRetrying
	logFailing
)

func (s logStatus) String() string {
	return [...]string{"ok", "catching up", "retrying", "failing"}[s]
}

type logHealth struct {
	log       ct.Log
	next      uint64
	size      uint64
	failures  int // consecutive
	lastErr   string
	lastErrAt time.Time
	lastOK    time.Time
}

func (h logHealth) lag() uint64 { return h.size - min(h.next, h.size) }

func (h logHealth) status() logStatus {
	switch {
	case h.failures >= failingAfter:
		return logFailing
	case h.failures > 0:
		return logRetrying
	case h.lag() > 0:
		return logCatchingUp
	}
	return logOK
}

// sink collects high-frequency events from background goroutines. The model polls
// it once per tick instead of receiving a tea.Msg per event: 60+ logs reporting
// progress after every batch would otherwise trigger hundreds of re-renders a second.
type sink struct {
	mu       sync.Mutex
	warnings []warning
	logs     map[string]*logHealth
	events   []sourceEvent // oldest first, at most maxSourceEvents
	eventSeq int
}

// sourceEvent is one line of search activity in the Sources tab.
type sourceEvent struct {
	seq    int // stable row identity while older events roll off
	at     time.Time
	source string
	level  ct.Level
	msg    string
}

const maxSourceEvents = 500

type warning struct {
	at   time.Time
	text string
}

type snapshot struct {
	lastWarning warning
	events      []sourceEvent // oldest first
	logs        []logHealth // sorted by operator, then name
	counts      [4]int      // indexed by logStatus
	totalLag    uint64
}

func newSink() *sink { return &sink{logs: map[string]*logHealth{}} }

// Write implements io.Writer so the ct package's warnf output lands here instead of
// on stderr, which would corrupt the alt screen.
func (s *sink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, line := range strings.Split(strings.TrimSpace(string(p)), "\n") {
		if line = strings.TrimPrefix(strings.TrimSpace(line), "ctq: "); line != "" {
			s.warnings = append(s.warnings, warning{time.Now(), line})
		}
	}
	if n := len(s.warnings); n > 50 {
		s.warnings = s.warnings[n-50:]
	}
	return len(p), nil
}

// trace is the ct.Tracer for searches. It runs on the search goroutine.
func (s *sink) trace(source string, level ct.Level, msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.eventSeq++
	// pgx joins per-address errors with newlines and tabs, which would break table rows.
	msg = strings.Join(strings.Fields(msg), " ")
	s.events = append(s.events, sourceEvent{seq: s.eventSeq, at: time.Now(), source: source, level: level, msg: msg})
	if n := len(s.events); n > maxSourceEvents {
		s.events = s.events[n-maxSourceEvents:]
	}
}

func (s *sink) health(l ct.Log) *logHealth {
	h := s.logs[l.URL]
	if h == nil {
		h = &logHealth{log: l}
		s.logs[l.URL] = h
	}
	return h
}

func (s *sink) progress(l ct.Log, next, size uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := s.health(l)
	h.next, h.size = next, size
	// Only a fully caught-up poll proves the log is healthy again. A partial
	// catch-up can be followed by another failure in the same poll.
	if next >= size {
		h.failures = 0
		h.lastOK = time.Now()
	}
}

func (s *sink) logError(l ct.Log, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := s.health(l)
	h.failures++
	h.lastErr = err.Error()
	h.lastErrAt = time.Now()
}

func (s *sink) resetLogs() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.logs = map[string]*logHealth{}
}

func (s *sink) snapshot() snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	var snap snapshot
	if n := len(s.warnings); n > 0 {
		snap.lastWarning = s.warnings[n-1]
	}
	snap.events = slices.Clone(s.events)
	for _, h := range s.logs {
		snap.logs = append(snap.logs, *h)
		snap.counts[h.status()]++
		snap.totalLag += h.lag()
	}
	sort.Slice(snap.logs, func(i, j int) bool {
		a, b := snap.logs[i].log, snap.logs[j].log
		if a.Operator != b.Operator {
			return a.Operator < b.Operator
		}
		return a.Name < b.Name
	})
	return snap
}
