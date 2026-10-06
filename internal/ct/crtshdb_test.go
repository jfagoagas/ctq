package ct

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestCA(t *testing.T) testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root"},
		NotBefore:             time.Now().Add(-10 * 365 * 24 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return testCA{cert, key}
}

func (ca testCA) issue(t *testing.T, serial int64, notBefore, notAfter time.Time, names ...string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestVerifyWithExpiredPin(t *testing.T) {
	ca, other := newTestCA(t), newTestCA(t)
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)
	now := time.Now()
	day := 24 * time.Hour
	parse := func(der []byte) *x509.Certificate {
		t.Helper()
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	expired := func(issuer testCA, serial int64, host string) *x509.Certificate {
		return parse(issuer.issue(t, serial, now.Add(-90*day), now.Add(-30*day), host))
	}

	pinned := expired(ca, 2, "crt.sh") // the one expired certificate the pin allows
	pin := spkiSHA256(pinned)
	for _, tc := range []struct {
		name    string
		leaf    *x509.Certificate
		host    string
		wantErr bool
	}{
		{"valid, not pinned", parse(ca.issue(t, 3, now.Add(-day), now.Add(day), "crt.sh")), "crt.sh", false},
		{"expired, pinned key", pinned, "crt.sh", false},
		{"expired, other key", expired(ca, 4, "crt.sh"), "crt.sh", true},
		{"expired, pinned key, wrong host", pinned, "evil.example", true},
		{"expired, untrusted root", expired(other, 5, "crt.sh"), "crt.sh", true},
		{"not yet valid", parse(ca.issue(t, 6, now.Add(day), now.Add(30*day), "crt.sh")), "crt.sh", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := verifyWithExpiredPin(tc.host, roots, pin)(tls.ConnectionState{PeerCertificates: []*x509.Certificate{tc.leaf}})
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if err != nil && classifyConnErr(fmt.Errorf("connect: %w", err)) != connFatal {
				t.Errorf("verification failure is retryable: %v", err)
			}
		})
	}

	// "Not yet valid" is reported as x509.Expired too; the pin must not cover it.
	future := parse(ca.issue(t, 7, now.Add(day), now.Add(30*day), "crt.sh"))
	if err := verifyWithExpiredPin("crt.sh", roots, spkiSHA256(future))(tls.ConnectionState{PeerCertificates: []*x509.Certificate{future}}); err == nil {
		t.Error("accepted a pinned certificate that is not valid yet")
	}
	if err := verifyWithExpiredPin("crt.sh", roots, pin)(tls.ConnectionState{}); err == nil {
		t.Error("accepted a connection without certificates")
	}
}

func TestFromDBRows(t *testing.T) {
	ca := newTestCA(t)
	now := time.Now()
	day := 24 * time.Hour
	current := func(serial int64, names ...string) []byte {
		return ca.issue(t, serial, now.Add(-day), now.Add(30*day), names...)
	}

	rows := []dbRow{
		{id: 20, der: current(1, "www.example.com", "example.com")}, // final certificate, logged after its precert
		{id: 10, der: current(1, "www.example.com", "example.com")}, // precert: same issuer and serial
		{id: 30, der: ca.issue(t, 2, now.Add(-90*day), now.Add(-30*day), "old.example.com")},
		{id: 40, der: current(3, "cdn.other.com")},
		{id: 50, der: []byte("not a certificate")},
	}

	certs, skipped := fromDBRows(rows, "example.com", true, false, now)
	if skipped != 1 {
		t.Errorf("skipped = %d, want 1", skipped)
	}
	if len(certs) != 1 {
		t.Fatalf("certs = %+v", certs)
	}
	c := certs[0]
	if c.ID != "10" || c.Source != "crtsh-db" || len(c.DNSNames) != 2 || IssuerCN(c.Issuer) != "Test Root" {
		t.Errorf("cert = %+v", c)
	}

	certs, _ = fromDBRows(rows, "example.com", true, true, now)
	if len(certs) != 2 {
		t.Errorf("with expired: %d certs, want 2", len(certs))
	}

	certs, _ = fromDBRows(rows, "example.com", false, true, now)
	if len(certs) != 1 || len(certs[0].DNSNames) != 1 || certs[0].DNSNames[0] != "example.com" {
		t.Errorf("exact: %+v", certs)
	}
}

func TestCrtShDBConfigIgnoresEnvironment(t *testing.T) {
	// A service file that tries to send the connection elsewhere, in plaintext.
	svc := filepath.Join(t.TempDir(), "pg_service.conf")
	if err := os.WriteFile(svc, []byte("[evil]\nhost=attacker.example\nport=6543\nuser=someone\ndbname=loot\nsslmode=disable\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PGSERVICEFILE", svc)
	t.Setenv("PGSERVICE", "evil")
	t.Setenv("PGHOST", "attacker.example")
	t.Setenv("PGPASSWORD", "secret")
	t.Setenv("PGSSLMODE", "allow")
	t.Setenv("PGSSLROOTCERT", "/nonexistent/root.crt")
	t.Setenv("PGTARGETSESSIONATTRS", "read-write")

	cfg, err := crtshDBConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Host != "crt.sh" || cfg.Port != 5432 || cfg.User != "guest" || cfg.Database != "certwatch" || cfg.Password != "" {
		t.Errorf("config = %s:%d %s/%s", cfg.Host, cfg.Port, cfg.User, cfg.Database)
	}
	if cfg.TLSConfig == nil || cfg.TLSConfig.VerifyConnection == nil || cfg.TLSConfig.ServerName != "crt.sh" || len(cfg.Fallbacks) != 0 {
		t.Error("TLS verification is not enforced")
	}
	if cfg.ValidateConnect != nil {
		t.Error("ValidateConnect would run an extra query")
	}
}

func TestClassifyConnErr(t *testing.T) {
	connect := func(t *testing.T, addr string) error {
		t.Helper()
		host, port, _ := net.SplitHostPort(addr)
		_, err := pgx.Connect(context.Background(), "host="+host+" port="+port+" user=guest dbname=x sslmode=disable connect_timeout=1")
		if err == nil {
			t.Fatal("connected")
		}
		return err
	}

	t.Run("refused", func(t *testing.T) {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := l.Addr().String()
		l.Close()
		if err := connect(t, addr); classifyConnErr(err) != connRetry {
			t.Errorf("kind = %d: %v", classifyConnErr(err), err)
		}
	})

	t.Run("timeout", func(t *testing.T) {
		// Accepts and never answers, like a firewall that drops packets after the handshake.
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				defer c.Close()
			}
		}()
		if err := connect(t, l.Addr().String()); classifyConnErr(err) != connTimeout {
			t.Errorf("kind = %d: %v", classifyConnErr(err), err)
		}
	})

	t.Run("tls verification", func(t *testing.T) {
		err := fmt.Errorf("wrapped: %w", &tls.CertificateVerificationError{Err: errors.New("bad chain")})
		if classifyConnErr(err) != connFatal {
			t.Error("not fatal")
		}
	})
}
