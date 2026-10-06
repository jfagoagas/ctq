package tui

import (
	"time"

	"github.com/jfagoagas/ctq/internal/ct"
)

// searchKey is everything that changes a search's answer. Scope and expired are
// fixed for a TUI session today, but they belong in the key so a cached answer
// can never be served for a different question.
type searchKey struct {
	domain     string
	source     string
	subdomains bool
	expired    bool
}

type cacheEntry struct {
	certs []ct.Certificate
	at    time.Time // when the search finished
	took  time.Duration
}

// searchCache keeps successful search results for the TUI session. crtsh-db waits
// about a minute per query and Cert Spotter's free quota is 10 queries per hour,
// so cycling sources or going back to a domain shouldn't pay that again.
//
// It takes the time as an argument instead of reading a clock, so the model's
// injectable now drives expiry.
type searchCache struct {
	ttl     time.Duration // <= 0 disables the cache
	entries map[searchKey]cacheEntry
}

func newSearchCache(ttl time.Duration) *searchCache {
	return &searchCache{ttl: ttl, entries: map[searchKey]cacheEntry{}}
}

func (c *searchCache) get(k searchKey, now time.Time) (cacheEntry, bool) {
	if c.ttl <= 0 {
		return cacheEntry{}, false
	}
	e, ok := c.entries[k]
	if !ok {
		return cacheEntry{}, false
	}
	if now.Sub(e.at) >= c.ttl {
		delete(c.entries, k)
		return cacheEntry{}, false
	}
	return e, true
}

func (c *searchCache) put(k searchKey, e cacheEntry) {
	if c.ttl <= 0 {
		return
	}
	c.entries[k] = e
}
