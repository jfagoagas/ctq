package ct

import (
	"context"
	"crypto/x509"
	"os"
	"testing"
	"time"
)

// Live wire-format checks against real CT logs. Run with CTQ_LIVE=1.
func TestLiveLogs(t *testing.T) {
	if os.Getenv("CTQ_LIVE") == "" {
		t.Skip("set CTQ_LIVE=1 to hit real CT logs")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	c := NewClient(30*time.Second, 2)

	logs, err := FetchLogs(ctx, c, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d logs in the Chrome list", len(logs))

	for _, l := range []Log{
		{Name: "Let's Encrypt Sycamore 2026h2 (tiled)", URL: "https://mon.sycamore.ct.letsencrypt.org/2026h2", Tiled: true},
		{Name: "Google Argon 2026h2 (RFC 6962)", URL: "https://ct.googleapis.com/logs/us1/argon2026h2"},
	} {
		t.Run(l.Name, func(t *testing.T) {
			r := NewReader(c, l)
			size, err := r.Size(ctx)
			if err != nil || size < TileWidth {
				t.Fatalf("size=%d err=%v", size, err)
			}
			entries, err := r.Fetch(ctx, 0, TileWidth)
			if err != nil {
				t.Fatal(err)
			}
			bad := 0
			for _, e := range entries {
				if e.DER == nil {
					bad++
					continue
				}
				if _, err := x509.ParseCertificate(e.DER); err != nil {
					bad++
				}
			}
			t.Logf("size=%d fetched=%d unparseable=%d", size, len(entries), bad)
			if bad > len(entries)/10 {
				t.Errorf("%d of %d entries failed to parse, wire format is probably wrong", bad, len(entries))
			}
		})
	}
}

// Live check of crt.sh's Postgres: TLS through its expired certificate, the pooler,
// and the query. Run with CTQ_LIVE=1; CTQ_LIVE_DOMAIN picks the domain. The guest
// pool queues every statement, so this takes a minute or more.
func TestLiveCrtShDB(t *testing.T) {
	if os.Getenv("CTQ_LIVE") == "" {
		t.Skip("set CTQ_LIVE=1 to hit crt.sh's database")
	}
	domain := os.Getenv("CTQ_LIVE_DOMAIN")
	if domain == "" {
		domain = "letsencrypt.org"
	}
	start := time.Now()
	certs, err := CrtShDB{Timeout: 4 * time.Minute, Retries: 4, Backoff: 5 * time.Second}.Search(context.Background(), domain, true, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) == 0 {
		t.Fatalf("no certificates for %s", domain)
	}
	valid := 0
	for _, c := range certs {
		if !c.Expired(time.Now()) {
			valid++
		}
	}
	t.Logf("%s: %d certificates (%d unexpired) in %s", domain, len(certs), valid, time.Since(start).Round(time.Second))
}
