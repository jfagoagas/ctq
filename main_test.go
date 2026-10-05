package main

import (
	"strings"
	"testing"
	"time"

	"github.com/jfagoagas/ctq/internal/ct"
)

func TestVersion(t *testing.T) {
	defer func(v, c, d string) { version, commit, date = v, c, d }(version, commit, date)

	version, commit, date = "0.1.0", "abc123", "2026-10-05T10:00:00Z"
	if buildVersion() != "0.1.0" {
		t.Errorf("ldflags version ignored: %q", buildVersion())
	}
	if s := versionString(); !strings.HasPrefix(s, "ctq 0.1.0 (go") || !strings.Contains(s, "commit abc123") {
		t.Errorf("versionString = %q", s)
	}

	// Test binaries have no module version, so this falls back to "dev".
	version, commit = "dev", ""
	if buildVersion() != "dev" {
		t.Errorf("buildVersion = %q", buildVersion())
	}
}

func TestWriteSearchNamesDedups(t *testing.T) {
	certs := []ct.Certificate{
		{DNSNames: []string{"b.example.com", "a.example.com"}},
		{DNSNames: []string{"a.example.com"}},
	}
	var out strings.Builder
	if err := writeSearch(&out, "names", certs, time.Now()); err != nil {
		t.Fatal(err)
	}
	if out.String() != "a.example.com\nb.example.com\n" {
		t.Errorf("got %q", out.String())
	}
}
