package tui

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/jfagoagas/ctq/internal/ct"
)

func TestSearchCache(t *testing.T) {
	k := searchKey{domain: "example.com", source: "crtsh", subdomains: true}
	c := newSearchCache(10 * time.Minute)

	if _, ok := c.get(k, now); ok {
		t.Fatal("hit on an empty cache")
	}
	c.put(k, cacheEntry{certs: []ct.Certificate{cert("1", "CN=x", now, "example.com")}, at: now})
	if e, ok := c.get(k, now.Add(9*time.Minute)); !ok || len(e.certs) != 1 {
		t.Fatalf("want a hit inside the TTL, got ok=%v %+v", ok, e)
	}
	for _, other := range []searchKey{
		{domain: "other.org", source: "crtsh", subdomains: true},
		{domain: "example.com", source: "certspotter", subdomains: true},
		{domain: "example.com", source: "crtsh"},                                  // exact instead of subdomains
		{domain: "example.com", source: "crtsh", subdomains: true, expired: true}, // with expired
	} {
		if _, ok := c.get(other, now); ok {
			t.Errorf("%+v hit the entry for %+v", other, k)
		}
	}
	if _, ok := c.get(k, now.Add(10*time.Minute)); ok {
		t.Fatal("hit at the TTL, want expired")
	}
	if _, ok := c.entries[k]; ok {
		t.Error("expired entry was not evicted")
	}

	off := newSearchCache(0)
	off.put(k, cacheEntry{at: now})
	if _, ok := off.get(k, now); ok {
		t.Error("TTL 0 must disable the cache")
	}
}

// cachedModel counts backend searches and lets the test move the clock.
type cachedModel struct {
	*Model
	calls int
	clock time.Time
	fail  bool
}

func newCachedModel(t *testing.T) *cachedModel {
	t.Helper()
	cm := &cachedModel{clock: now}
	cm.Model = New(context.Background(), Options{
		Domain: "example.com", Subdomains: true, CacheTTL: 15 * time.Minute,
		Backend: Backend{
			Search: func(_ context.Context, domain, source string, _ io.Writer) ([]ct.Certificate, error) {
				cm.calls++
				if cm.fail {
					return nil, errors.New("pool refused the connection")
				}
				c := cert("echo", "CN=x", now, domain)
				c.Source = source
				return []ct.Certificate{c}, nil
			},
			Watch: func(ctx context.Context, _ string, _ WatchHooks) error { <-ctx.Done(); return ctx.Err() },
		},
	})
	cm.now = func() time.Time { return cm.clock }
	cm.Update(tea.WindowSizeMsg{Width: 140, Height: 30})
	return cm
}

// run executes cmd, feeds any search result back and reports whether the backend was queried.
func (cm *cachedModel) run(cmd tea.Cmd) bool {
	before := cm.calls
	if cmd != nil {
		msgs := []tea.Msg{cmd()}
		if batch, ok := msgs[0].(tea.BatchMsg); ok {
			msgs = msgs[:0]
			for _, c := range batch {
				if c != nil {
					msgs = append(msgs, c())
				}
			}
		}
		for _, msg := range msgs {
			if done, ok := msg.(searchDoneMsg); ok {
				cm.Update(done)
			}
		}
	}
	return cm.calls > before
}

func (cm *cachedModel) press(k string) bool {
	_, cmd := cm.Update(key(k))
	return cm.run(cmd)
}

func (cm *cachedModel) status() string { return ansi.Strip(cm.statusView()) }

func TestCacheMissThenHitOnDomainSwitch(t *testing.T) {
	cm := newCachedModel(t)
	if !cm.run(cm.search()) {
		t.Fatal("first search must hit the backend")
	}
	if cm.fromCache || strings.Contains(cm.status(), "cached") {
		t.Fatalf("fresh result shown as cached: %q", cm.status())
	}

	if !cm.run(cm.switchDomain("other.org")) {
		t.Fatal("a new domain must miss the cache")
	}
	cm.clock = cm.clock.Add(3 * time.Minute)
	if cm.run(cm.switchDomain("example.com")) {
		t.Fatal("going back to a domain inside the TTL must not search again")
	}
	if cm.searching || len(cm.history) != 1 || cm.history[0].DNSNames[0] != "example.com" {
		t.Fatalf("cached history not shown: searching=%v %+v", cm.searching, cm.history)
	}
	if !cm.fromCache || !strings.Contains(cm.status(), "cached, fetched 3m ago") {
		t.Errorf("status should say the result is cached and its age: %q", cm.status())
	}
	if _, ok := cm.names["example.com"]; !ok {
		t.Error("names were not rebuilt from the cached history")
	}
	cm.Update(key("5"))
	if !strings.Contains(ansi.Strip(cm.render()), "from the cache") {
		t.Error("Sources tab should record the cache hit")
	}
}

func TestCacheExpires(t *testing.T) {
	cm := newCachedModel(t)
	cm.run(cm.search())
	cm.run(cm.switchDomain("other.org"))
	cm.clock = cm.clock.Add(15 * time.Minute)
	if !cm.run(cm.switchDomain("example.com")) {
		t.Fatal("an entry at its TTL must be searched again")
	}
	if cm.fromCache {
		t.Error("a fresh search must not be marked cached")
	}
}

func TestSourceCycleUsesCache(t *testing.T) {
	cm := newCachedModel(t)
	cm.run(cm.search())
	for _, src := range []string{"crtsh-db", "crtsh", "certspotter"} {
		if !cm.press("s") || cm.source != src {
			t.Fatalf("source %s should miss the cache (now %s)", src, cm.source)
		}
	}
	if cm.press("s") || cm.source != "auto" {
		t.Fatalf("back on auto, s must reuse the cached result (source %s, calls %d)", cm.source, cm.calls)
	}
	if !cm.fromCache || cm.history[0].Source != "auto" {
		t.Errorf("showing the wrong cached result: fromCache=%v %+v", cm.fromCache, cm.history)
	}
}

func TestRefreshBypassesCache(t *testing.T) {
	cm := newCachedModel(t)
	cm.run(cm.search())
	cm.run(cm.switchDomain("other.org"))
	cm.run(cm.switchDomain("example.com"))
	if !cm.fromCache {
		t.Fatal("setup: expected a cached result")
	}
	cm.clock = cm.clock.Add(time.Minute)
	if !cm.press("r") {
		t.Fatal("r must always query the backend")
	}
	if cm.fromCache || strings.Contains(cm.status(), "cached") {
		t.Errorf("after r the result is fresh: %q", cm.status())
	}
	// And r refreshed the entry: its age restarts from the r.
	cm.run(cm.switchDomain("other.org"))
	cm.clock = cm.clock.Add(14 * time.Minute)
	if cm.run(cm.switchDomain("example.com")) || !strings.Contains(cm.status(), "fetched 14m ago") {
		t.Errorf("r should have refreshed the cache entry: %q", cm.status())
	}
}

func TestFailedSearchNotCached(t *testing.T) {
	cm := newCachedModel(t)
	cm.fail = true
	cm.run(cm.search())
	cm.run(cm.switchDomain("other.org"))
	cm.fail = false
	if !cm.run(cm.switchDomain("example.com")) {
		t.Fatal("a failed search must not be cached")
	}
}

func TestCacheHitSupersedesRunningSearch(t *testing.T) {
	cm := newCachedModel(t)
	cm.run(cm.search())
	cm.run(cm.switchDomain("other.org"))
	cm.startSearch() // r on other.org, still running
	stale := cm.searchGen
	cm.run(cm.switchDomain("example.com"))
	cm.Update(searchDoneMsg{gen: stale, certs: []ct.Certificate{cert("1", "CN=x", now, "other.org")}})
	if cm.history[0].DNSNames[0] != "example.com" || cm.searching {
		t.Fatalf("the old search overwrote the cached result: %+v searching=%v", cm.history, cm.searching)
	}
}
