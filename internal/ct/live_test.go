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
