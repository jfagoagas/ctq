package ct

import (
	"crypto/x509"
	"slices"
	"testing"
)

// Terminal control sequences that CT data can carry: an OSC that retitles the
// window (ended by BEL) and a CSI that clears the screen.
const (
	osc = "\x1b]0;evil\x07"
	csi = "\x1b[2J"
)

func TestSanitize(t *testing.T) {
	for in, want := range map[string]string{
		"www.example.com":           "www.example.com",
		"CN=R12,O=Let's Encrypt":    "CN=R12,O=Let's Encrypt",
		"münchen.example":           "münchen.example",
		osc + "a.example.com":       `\x1b]0;evil\x07a.example.com`,
		csi + "b.example.com":       `\x1b[2Jb.example.com`,
		"c\x9b31m.example.com":      `c\x9b31m.example.com`, // C1 CSI as a single invalid byte
		"d\u009b31m.example.com":    `d\x9b31m.example.com`, // and as the U+009B rune
		"e\u202e.example.com":       `e\u202e.example.com`,  // right-to-left override
		"f\U000e0041.example.com":   `f\U000e0041.example.com`,
		"tab\tand\nnewline\rreturn": `tab\x09and\x0anewline\x0dreturn`,
	} {
		if got := sanitize(in); got != want {
			t.Errorf("sanitize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestScopeSanitizes(t *testing.T) {
	got := Scope([]string{osc + ".example.com", "www.example.com", csi + "x.other.net"}, "example.com", true)
	if want := []string{`\x1b]0;evil\x07.example.com`, "www.example.com"}; !slices.Equal(got, want) {
		t.Errorf("Scope = %q, want %q", got, want)
	}
}

func TestFromX509Sanitizes(t *testing.T) {
	// Go rejects control characters in SANs it parses, but not in DN attributes.
	x := &x509.Certificate{DNSNames: []string{csi + "a.example.com"}}
	x.Subject.CommonName = osc + ".example.com"
	x.Issuer.CommonName = "Evil CA" + osc
	c, ok := fromX509("1", "log", x, "example.com", true)
	if !ok {
		t.Fatal("out of scope")
	}
	// Names are lowercased before matching, hence 2j.
	if want := []string{`\x1b[2ja.example.com`, `\x1b]0;evil\x07.example.com`}; !slices.Equal(c.DNSNames, want) {
		t.Errorf("DNSNames = %q, want %q", c.DNSNames, want)
	}
	// Go's DN formatting escapes the semicolon itself.
	if want := `CN=Evil CA\x1b]0\;evil\x07`; c.Issuer != want {
		t.Errorf("Issuer = %q, want %q", c.Issuer, want)
	}
}
