package ct

import (
	"bytes"
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
	for n, want := range map[uint64]string{
		0:       "000",
		5:       "005",
		999:     "999",
		1000:    "x001/000",
		1234067: "x001/x234/067",
	} {
		if got := tilePath(n); got != want {
			t.Errorf("tilePath(%d) = %q, want %q", n, got, want)
		}
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
		if got := Matches(c.name, "example.com", c.subdomains); got != c.want {
			t.Errorf("Matches(%q, sub=%v) = %v", c.name, c.subdomains, got)
		}
	}
	got := Scope([]string{"B.Example.com.", "b.example.com", "cdn.other.net", "", "Acme Inc"}, "example.com", true)
	if len(got) != 1 || got[0] != "b.example.com" {
		t.Errorf("Scope = %v", got)
	}
}

func TestNormalizeDomain(t *testing.T) {
	for in, want := range map[string]string{
		"Example.COM.":       "example.com",
		"*.example.com":      "example.com",
		" sub.example.co.uk": "sub.example.co.uk",
	} {
		if got, err := NormalizeDomain(in); err != nil || got != want {
			t.Errorf("NormalizeDomain(%q) = %q, %v", in, got, err)
		}
	}
	// % and _ are SQL LIKE wildcards on crt.sh. They must never pass.
	for _, bad := range []string{"%.com", "ex_ample.com", "localhost", "", "a..com", "https://example.com"} {
		if _, err := NormalizeDomain(bad); err == nil {
			t.Errorf("NormalizeDomain(%q) accepted", bad)
		}
	}
}

func TestIssuerCN(t *testing.T) {
	for in, want := range map[string]string{
		"C=US, O=Let's Encrypt, CN=R12": "R12",
		"CN=R10,O=Let's Encrypt,C=US":   "R10",
		"O=No CN":                       "O=No CN",
	} {
		if got := IssuerCN(in); got != want {
			t.Errorf("IssuerCN(%q) = %q", in, got)
		}
	}
}
