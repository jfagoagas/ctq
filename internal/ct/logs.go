package ct

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Entry is one log entry. DER is the leaf certificate, or the precertificate for
// precert entries (same SANs, and unlike the TBS it parses as a full certificate).
// DER is nil when the entry could not be decoded.
type Entry struct {
	Index   uint64
	DER     []byte
	Precert bool
}

// LogReader reads a CT log by index. Fetch returns at least one entry starting at
// start, possibly fewer than end-start: servers cap batch sizes.
type LogReader interface {
	Size(ctx context.Context) (uint64, error)
	Fetch(ctx context.Context, start, end uint64) ([]Entry, error)
}

func NewReader(c *Client, l Log) LogReader {
	if l.Tiled {
		return &TiledLog{Client: c, Base: l.URL}
	}
	return &RFC6962Log{Client: c, Base: l.URL}
}

const (
	x509Entry    = 0
	precertEntry = 1
)

var errTruncated = errors.New("truncated TLS structure")

// tlsReader decodes the TLS presentation language used by RFC 6962 and static-ct-api.
// The first error sticks, so callers check once at the end.
type tlsReader struct {
	b   []byte
	err error
}

func (r *tlsReader) bytes(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || n > len(r.b) {
		r.err = errTruncated
		return nil
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out
}

func (r *tlsReader) uint(n int) uint64 {
	var v uint64
	for _, x := range r.bytes(n) {
		v = v<<8 | uint64(x)
	}
	return v
}

// vec reads a variable-length vector whose length prefix is lenBytes wide.
// Prefixes are at most 3 bytes, and bytes() rejects a negative n anyway.
func (r *tlsReader) vec(lenBytes int) []byte { return r.bytes(int(r.uint(lenBytes))) } //nolint:gosec // G115, see above

// --- RFC 6962 ---

type RFC6962Log struct {
	Client *Client
	Base   string
}

func (l *RFC6962Log) Size(ctx context.Context) (uint64, error) {
	resp, err := l.Client.Get(ctx, l.Base+"/ct/v1/get-sth", nil)
	if err != nil {
		return 0, err
	}
	var sth struct {
		TreeSize uint64 `json:"tree_size"`
	}
	if err := json.Unmarshal(resp.Body, &sth); err != nil {
		return 0, fmt.Errorf("get-sth: %w", err)
	}
	return sth.TreeSize, nil
}

func (l *RFC6962Log) Fetch(ctx context.Context, start, end uint64) ([]Entry, error) {
	// get-entries takes an inclusive end.
	resp, err := l.Client.Get(ctx, fmt.Sprintf("%s/ct/v1/get-entries?start=%d&end=%d", l.Base, start, end-1), nil)
	if err != nil {
		return nil, err
	}
	var body struct {
		Entries []struct {
			LeafInput []byte `json:"leaf_input"` // encoding/json decodes base64 into []byte
			ExtraData []byte `json:"extra_data"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(resp.Body, &body); err != nil {
		return nil, fmt.Errorf("get-entries: %w", err)
	}
	if len(body.Entries) == 0 {
		return nil, fmt.Errorf("get-entries returned no entries for [%d, %d)", start, end)
	}
	if n := uint64(len(body.Entries)); n > end-start {
		body.Entries = body.Entries[:end-start]
	}
	out := make([]Entry, len(body.Entries))
	for i, e := range body.Entries {
		idx := start + uint64(i)
		out[i], err = ParseRFC6962Leaf(idx, e.LeafInput, e.ExtraData)
		if err != nil {
			// Keep the slot so index accounting stays exact. The caller counts it as a parse error.
			out[i] = Entry{Index: idx}
		}
	}
	return out, nil
}

// ParseRFC6962Leaf decodes a MerkleTreeLeaf. Precert leaves only carry the TBS, so the
// full precertificate is read from extra_data (PrecertChainEntry.pre_certificate).
func ParseRFC6962Leaf(index uint64, leafInput, extraData []byte) (Entry, error) {
	r := &tlsReader{b: leafInput}
	version, leafType := r.uint(1), r.uint(1)
	r.uint(8) // timestamp
	entryType := r.uint(2)
	if r.err != nil {
		return Entry{}, r.err
	}
	if version != 0 || leafType != 0 {
		return Entry{}, fmt.Errorf("unsupported leaf version %d type %d", version, leafType)
	}
	switch entryType {
	case x509Entry:
		der := r.vec(3)
		return Entry{Index: index, DER: der}, r.err
	case precertEntry:
		x := &tlsReader{b: extraData}
		der := x.vec(3)
		return Entry{Index: index, DER: der, Precert: true}, x.err
	}
	return Entry{}, fmt.Errorf("unknown entry type %d", entryType)
}

// --- static-ct-api (tiled logs, https://c2sp.org/static-ct-api) ---

const TileWidth = 256

type TiledLog struct {
	Client *Client
	Base   string
}

func (l *TiledLog) Size(ctx context.Context) (uint64, error) {
	resp, err := l.Client.Get(ctx, l.Base+"/checkpoint", nil)
	if err != nil {
		return 0, err
	}
	// Checkpoint note body: origin line, tree size line, root hash line, then signatures.
	lines := strings.SplitN(string(resp.Body), "\n", 3)
	if len(lines) < 2 {
		return 0, fmt.Errorf("checkpoint: malformed")
	}
	return strconv.ParseUint(lines[1], 10, 64)
}

// Fetch reads the data tile that contains start. end must be a tile boundary or the
// current tree size, because partial tiles are published at exactly size%256 width.
func (l *TiledLog) Fetch(ctx context.Context, start, end uint64) ([]Entry, error) {
	tile := start / TileWidth
	tileStart := tile * TileWidth
	width := min(end-tileStart, TileWidth)
	path := tilePath(tile)
	if width < TileWidth {
		path += fmt.Sprintf(".p/%d", width)
	}
	resp, err := l.Client.Get(ctx, l.Base+"/tile/data/"+path, nil)
	if err != nil {
		return nil, err
	}
	all, err := ParseTile(tileStart, resp.Body)
	if err != nil {
		return nil, err
	}
	var out []Entry
	for _, e := range all {
		if e.Index >= start && e.Index < tileStart+width {
			out = append(out, e)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("tile %s has no entries at or after %d", path, start)
	}
	return out, nil
}

// tilePath encodes a tile index as 3-digit groups, all but the last prefixed with x:
// 1234067 -> x001/x234/067.
func tilePath(n uint64) string {
	p := fmt.Sprintf("%03d", n%1000)
	for n /= 1000; n > 0; n /= 1000 {
		p = fmt.Sprintf("x%03d/", n%1000) + p
	}
	return p
}

// ParseTile decodes a data tile: a concatenation of TileLeaf structures.
func ParseTile(first uint64, data []byte) ([]Entry, error) {
	r := &tlsReader{b: data}
	var out []Entry
	for i := first; len(r.b) > 0; i++ {
		r.uint(8) // timestamp
		e := Entry{Index: i}
		switch et := r.uint(2); et {
		case x509Entry:
			e.DER = r.vec(3)
			r.vec(2) // extensions
			r.vec(2) // certificate_chain fingerprints
		case precertEntry:
			r.bytes(32) // issuer_key_hash
			r.vec(3)    // TBSCertificate
			r.vec(2)    // extensions
			e.DER = r.vec(3)
			e.Precert = true
			r.vec(2) // precertificate_chain fingerprints
		default:
			if r.err == nil {
				return out, fmt.Errorf("tile entry %d: unknown entry type %d", i, et)
			}
		}
		if r.err != nil {
			return out, fmt.Errorf("tile entry %d: %w", i, r.err)
		}
		out = append(out, e)
	}
	return out, nil
}
