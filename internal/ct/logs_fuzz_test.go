package ct

import (
	"math"
	"strings"
	"testing"
)

// The parsers below read bytes straight off the network, from logs we don't control.
// Whatever arrives, they must return an error instead of panicking or reading out of
// bounds.

func FuzzParseTile(f *testing.F) {
	d := fakeDER(1)
	f.Add(uint64(0), tileX509(d))
	f.Add(uint64(512), tilePrecert(d))
	f.Add(uint64(512), cat(tileX509(d), tilePrecert(d)))
	f.Add(uint64(256), dataTile(256, 3))
	f.Add(uint64(0), tileX509(d)[:30])
	f.Add(uint64(math.MaxUint64), cat(tileX509(d), tileX509(d)))
	f.Add(uint64(0), []byte{})
	f.Fuzz(func(t *testing.T, first uint64, data []byte) {
		entries, err := ParseTile(first, data)
		if err == nil && len(data) > 0 && len(entries) == 0 {
			t.Fatal("non-empty tile parsed to no entries without an error")
		}
		for k, e := range entries {
			if want := first + uint64(k); e.Index != want {
				t.Fatalf("entry %d has index %d, want %d", k, e.Index, want)
			}
			if len(e.DER) > len(data) {
				t.Fatalf("entry %d: %d-byte DER from a %d-byte tile", k, len(e.DER), len(data))
			}
		}
	})
}

func FuzzParseRFC6962Leaf(f *testing.F) {
	d := fakeDER(1)
	f.Add(uint64(7), rfcX509Leaf(d), []byte(nil))
	f.Add(uint64(8), rfcPrecertLeaf(), rfcPrecertExtra(d))
	f.Add(uint64(0), rfcX509Leaf(d)[:20], []byte(nil))
	f.Add(uint64(0), cat([]byte{1, 0}, rfcX509Leaf(d)[2:]), []byte(nil))
	f.Add(uint64(0), rfcPrecertLeaf(), rfcPrecertExtra(d)[:2])
	f.Fuzz(func(t *testing.T, index uint64, leafInput, extraData []byte) {
		e, err := ParseRFC6962Leaf(index, leafInput, extraData)
		src := leafInput
		if e.Precert {
			src = extraData
		}
		if len(e.DER) > len(src) {
			t.Fatalf("%d-byte DER from %d bytes of input", len(e.DER), len(src))
		}
		if err == nil && e.Index != index {
			t.Fatalf("index %d, want %d", e.Index, index)
		}
	})
}

func FuzzParseCheckpoint(f *testing.F) {
	f.Add(checkpointBody(0))
	f.Add(checkpointBody(300))
	f.Add(checkpointBody(math.MaxUint64))
	f.Add([]byte("example.com/log\n7"))
	f.Add([]byte("example.com/log"))
	f.Add([]byte("example.com/log\n-1\n"))
	f.Add([]byte("example.com/log\n18446744073709551616\n"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, body []byte) {
		size, err := parseCheckpoint(body)
		if err != nil {
			if size != 0 || !strings.HasPrefix(err.Error(), "checkpoint: ") {
				t.Fatalf("parseCheckpoint = %d, %q", size, err)
			}
			return
		}
		// Success means the second line is a bare decimal number.
		line := strings.SplitN(string(body), "\n", 3)[1]
		if line == "" || strings.Trim(line, "0123456789") != "" {
			t.Fatalf("accepted size line %q as %d", line, size)
		}
	})
}
