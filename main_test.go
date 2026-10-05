package main

import (
	"strings"
	"testing"
	"time"

	"github.com/jfagoagas/ctq/internal/ct"
)

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
