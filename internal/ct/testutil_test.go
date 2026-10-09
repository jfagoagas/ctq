package ct

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"testing"
	"time"
)

func makeCert(t *testing.T, serial int64, names ...string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: names[0]},
		Issuer:       pkix.Name{CommonName: "Test CA"},
		DNSNames:     names,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// tls helpers build the same wire structures the parsers read.
func u(n int, v int) []byte {
	b := make([]byte, n)
	for i := n - 1; i >= 0; i-- {
		b[i] = byte(v)
		v >>= 8
	}
	return b
}

func vec(n int, data []byte) []byte { return append(u(n, len(data)), data...) }

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func rfcX509Leaf(der []byte) []byte {
	return cat([]byte{0, 0}, u(8, 1), u(2, x509Entry), vec(3, der), vec(2, nil))
}

func rfcPrecertLeaf() []byte {
	return cat([]byte{0, 0}, u(8, 1), u(2, precertEntry), make([]byte, 32), vec(3, []byte("tbs")), vec(2, nil))
}

func rfcPrecertExtra(der []byte) []byte { return cat(vec(3, der), vec(3, nil)) }

func tileX509(der []byte) []byte {
	return cat(u(8, 1), u(2, x509Entry), vec(3, der), vec(2, nil), vec(2, make([]byte, 32)))
}

func tilePrecert(der []byte) []byte {
	return cat(u(8, 1), u(2, precertEntry), make([]byte, 32), vec(3, []byte("tbs")), vec(2, nil), vec(3, der), vec(2, nil))
}

// fakeDER is a stand-in leaf certificate. The log parsers never decode DER, so tests
// that need many entries skip the key generation in makeCert.
func fakeDER(index uint64) []byte { return []byte(fmt.Sprintf("der-%d", index)) }

// dataTile builds a data tile of n x509 leaves starting at first, each carrying fakeDER.
func dataTile(first, n uint64) []byte {
	var out []byte
	for i := first; i < first+n; i++ {
		out = append(out, tileX509(fakeDER(i))...)
	}
	return out
}

// checkpointBody builds a static-ct-api checkpoint note for a tree of the given size.
func checkpointBody(size uint64) []byte {
	return []byte(fmt.Sprintf("example.com/log\n%d\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n\n— example.com/log AAAAAAAA\n", size))
}
