package ct

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgproto3"
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
	until := now.Add(365 * day)
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
			err := verifyWithExpiredPin(tc.host, roots, pin, until, nil)(tls.ConnectionState{PeerCertificates: []*x509.Certificate{tc.leaf}})
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
	if err := verifyWithExpiredPin("crt.sh", roots, spkiSHA256(future), until, nil)(tls.ConnectionState{PeerCertificates: []*x509.Certificate{future}}); err == nil {
		t.Error("accepted a pinned certificate that is not valid yet")
	}
	if err := verifyWithExpiredPin("crt.sh", roots, pin, until, nil)(tls.ConnectionState{}); err == nil {
		t.Error("accepted a connection without certificates")
	}
}

func TestVerifyWithExpiredPinEnds(t *testing.T) {
	ca := newTestCA(t)
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)
	day := 24 * time.Hour
	// Expired a month before the pin ends, like crt.sh's certificate on port 5432.
	leaf, err := x509.ParseCertificate(ca.issue(t, 2, crtshDBPinUntil.Add(-90*day), crtshDBPinUntil.Add(-30*day), "crt.sh"))
	if err != nil {
		t.Fatal(err)
	}
	cs := tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
	at := func(t time.Time) func() time.Time { return func() time.Time { return t } }

	if err := verifyWithExpiredPin("crt.sh", roots, spkiSHA256(leaf), crtshDBPinUntil, at(crtshDBPinUntil))(cs); err != nil {
		t.Errorf("rejected at the pin's last second: %v", err)
	}
	err = verifyWithExpiredPin("crt.sh", roots, spkiSHA256(leaf), crtshDBPinUntil, at(crtshDBPinUntil.Add(time.Second)))(cs)
	if err == nil {
		t.Fatal("accepted the pinned expired certificate after the pin ended")
	}
	if !strings.Contains(err.Error(), "issues/9") || !strings.Contains(err.Error(), "2026-12-21") {
		t.Errorf("error does not explain itself: %v", err)
	}
	if classifyConnErr(fmt.Errorf("connect: %w", err)) != connFatal {
		t.Errorf("an ended pin is retryable: %v", err)
	}
}

type fakeRows struct {
	rows [][]byte
	next int
}

func (f *fakeRows) Next() bool { f.next++; return f.next <= len(f.rows) }
func (f *fakeRows) Err() error { return nil }
func (f *fakeRows) Scan(dest ...any) error {
	*dest[0].(*int64) = int64(f.next)
	*dest[1].(*[]byte) = f.rows[f.next-1]
	return nil
}

func TestCollectRowsCaps(t *testing.T) {
	der := make([]byte, 1000)
	rows := func(n int) *fakeRows { return &fakeRows{rows: slices.Repeat([][]byte{der}, n)} }
	for _, tc := range []struct {
		name              string
		n                 int
		maxRows, maxBytes int
		wantErr           bool
	}{
		{"under both caps", 10, 10, 10 * 1000, false},
		{"one row too many", 11, 10, 1 << 20, true},
		{"one byte too many", 10, 100, 10*1000 - 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := rows(tc.n)
			raw, err := collectRows(f, tc.maxRows, tc.maxBytes)
			if !tc.wantErr {
				if err != nil || len(raw) != tc.n {
					t.Fatalf("%d rows, err = %v", len(raw), err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "narrower domain") {
				t.Fatalf("err = %v", err)
			}
			if f.next > tc.n {
				t.Error("read past the cap")
			}
		})
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

	parsed, failed := parseDBRows(context.Background(), rows)
	if !slices.Equal(failed, []int64{50}) {
		t.Errorf("failed = %v, want [50]", failed)
	}
	certs := scopeDBCerts(parsed, "example.com", true, false, now)
	if len(certs) != 1 {
		t.Fatalf("certs = %+v", certs)
	}
	c := certs[0]
	if c.ID != "10" || c.Source != "crtsh-db" || len(c.DNSNames) != 2 || IssuerCN(c.Issuer) != "Test Root" {
		t.Errorf("cert = %+v", c)
	}

	certs = scopeDBCerts(parsed, "example.com", true, true, now)
	if len(certs) != 2 {
		t.Errorf("with expired: %d certs, want 2", len(certs))
	}

	certs = scopeDBCerts(parsed, "example.com", false, true, now)
	if len(certs) != 1 || len(certs[0].DNSNames) != 1 || certs[0].DNSNames[0] != "example.com" {
		t.Errorf("exact: %+v", certs)
	}
}

func readPEM(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	p, _ := pem.Decode(b)
	if p == nil {
		t.Fatalf("%s: no PEM block", name)
	}
	return p.Bytes
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// crt.sh ids 2854374595, 2854374664 and 2854376823 are copies of the example.org
// certificate 987119772 with the outer signature algorithm swapped for a private
// OID (1.3.6.1.4.1.46450.5.123.4.x). The TBS is byte-identical, so Go rejects
// them while crt.sh indexes them under example.com.
func TestFallbackForRejectedCert(t *testing.T) {
	tampered := dbRow{id: 2854374664, der: readPEM(t, "crtsh-2854374664.pem")}
	orig := dbRow{id: 987119772, der: readPEM(t, "crtsh-987119772.pem")}

	if _, err := x509.ParseCertificate(tampered.der); err == nil || !strings.Contains(err.Error(), "signature algorithm") {
		t.Fatalf("fixture no longer exercises the fallback: err = %v", err)
	}
	parsed, failed := parseDBRows(context.Background(), []dbRow{tampered, orig})
	if len(parsed) != 1 || parsed[0].id != orig.id || !slices.Equal(failed, []int64{tampered.id}) {
		t.Fatalf("parsed = %+v, failed = %v", parsed, failed)
	}

	// What crtshDBFallbackQuery returned for 2854374664 on 2026-10-06.
	nb := time.Date(2018, 11, 28, 0, 0, 0, 0, time.UTC)
	na := time.Date(2020, 12, 2, 12, 0, 0, 0, time.UTC)
	issuerName := "C=US, O=DigiCert Inc, CN=DigiCert SHA2 Secure Server CA"
	row := dbFallbackRow{
		id:         tampered.id,
		issuerDER:  mustHex(t, "304d310b300906035504061302555331153013060355040a130c446967694365727420496e63312730250603550403131e446967694365727420534841322053656375726520536572766572204341"),
		issuerName: &issuerName,
		serial:     mustHex(t, "0fd078dd48f1a2bd4d0f2ba96b6038fe"),
		notBefore:  &nb,
		notAfter:   &na,
		names:      []string{"www.example.org", "example.com", "example.edu", "example.net", "example.org", "www.example.com", "www.example.edu", "www.example.net", "www.example.org"},
	}
	fb, ok := row.cert()
	if !ok {
		t.Fatal("readable fallback row rejected")
	}
	if fb.key != parsed[0].key {
		t.Error("crt.sh's issuer and serial don't match Go's: tampered copies would not deduplicate")
	}

	// On its own the rejected row reaches History and Names, formatted like a parsed row.
	certs := scopeDBCerts([]dbCert{fb}, "example.com", true, true, time.Now())
	want := Certificate{
		ID: "2854374664", Source: "crtsh-db", Issuer: "CN=DigiCert SHA2 Secure Server CA,O=DigiCert Inc,C=US",
		DNSNames: []string{"example.com", "www.example.com"}, NotBefore: nb, NotAfter: na,
	}
	if len(certs) != 1 || !reflect.DeepEqual(certs[0], want) {
		t.Errorf("fallback only:\n got %+v\nwant %+v", certs, want)
	}
	if got := scopeDBCerts(parsed, "example.com", true, true, time.Now()); !reflect.DeepEqual(got[0], Certificate{
		ID: "987119772", Source: "crtsh-db", Issuer: want.Issuer, DNSNames: want.DNSNames, NotBefore: nb, NotAfter: na,
	}) {
		t.Errorf("parsed row differs from its fallback twin: %+v", got)
	}

	// Next to the real certificate, the copy collapses into it.
	certs = scopeDBCerts(append(slices.Clone(parsed), fb), "example.com", true, true, time.Now())
	if len(certs) != 1 || certs[0].ID != "987119772" {
		t.Errorf("with the real certificate: %+v", certs)
	}

	// Without a parseable issuer DN, crt.sh's text is used.
	noDN := row
	noDN.issuerDER = []byte{0x30, 0x03, 0x02, 0x01, 0x01}
	if c, ok := noDN.cert(); !ok || c.issuer != issuerName {
		t.Errorf("issuer = %q, ok = %v", c.issuer, ok)
	}

	// Rows crt.sh can't read either stay skipped.
	for name, mutate := range map[string]func(*dbFallbackRow){
		"no dates":  func(r *dbFallbackRow) { r.notBefore, r.notAfter = nil, nil },
		"no issuer": func(r *dbFallbackRow) { r.issuerDER = nil },
		"no serial": func(r *dbFallbackRow) { r.serial = nil },
	} {
		r := row
		mutate(&r)
		if _, ok := r.cert(); ok {
			t.Errorf("%s: accepted", name)
		}
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

func TestCrtShDBConnectRetryBudget(t *testing.T) {
	var (
		refused = errors.New("dial tcp 1.2.3.4:5432: connect: connection refused")
		full    = errors.New("FATAL: no more connections allowed (max_client_conn) (SQLSTATE 08P01)")
		timeout = fmt.Errorf("dial tcp 1.2.3.4:5432: %w", os.ErrDeadlineExceeded)
		badCert = fmt.Errorf("tls: %w", &tls.CertificateVerificationError{Err: errors.New("bad chain")})
	)
	const backoff = time.Second
	for _, tc := range []struct {
		name      string
		errs      []error // one per dial; nil connects
		wantDials int
		wantSleep []time.Duration
		wantErr   error
	}{
		{"refused uses every retry", []error{refused, refused, refused, refused, refused}, 5,
			[]time.Duration{backoff, 2 * backoff, 4 * backoff, 8 * backoff}, refused},
		{"max_client_conn uses every retry", []error{full, full, full, full, full}, 5,
			[]time.Duration{backoff, 2 * backoff, 4 * backoff, 8 * backoff}, full},
		{"refused, then connects", []error{refused, full, nil}, 3,
			[]time.Duration{backoff, 2 * backoff}, nil},
		{"timeout is retried once", []error{timeout, timeout}, 2,
			[]time.Duration{backoff}, timeout},
		{"second timeout stops the loop", []error{refused, timeout, refused, timeout}, 4,
			[]time.Duration{backoff, 2 * backoff, 4 * backoff}, timeout},
		{"one timeout keeps the budget", []error{timeout, refused, refused, refused, refused}, 5,
			[]time.Duration{backoff, 2 * backoff, 4 * backoff, 8 * backoff}, refused},
		{"timeout, then connects", []error{timeout, nil}, 2,
			[]time.Duration{backoff}, nil},
		{"TLS failure is not retried", []error{badCert}, 1, nil, badCert},
		{"TLS failure after a retry", []error{refused, badCert}, 2,
			[]time.Duration{backoff}, badCert},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dials := 0
			var slept []time.Duration
			s := CrtShDB{
				Retries: 4,
				Backoff: backoff,
				dial: func(context.Context, *pgx.ConnConfig) (*pgx.Conn, error) {
					if dials >= len(tc.errs) {
						t.Fatalf("dial %d: past the expected %d", dials+1, len(tc.errs))
					}
					dials++
					return nil, tc.errs[dials-1]
				},
				after: func(d time.Duration) <-chan time.Time {
					slept = append(slept, d)
					ch := make(chan time.Time, 1)
					ch <- time.Time{}
					return ch
				},
			}
			_, err := s.connect(context.Background())
			if dials != tc.wantDials {
				t.Errorf("dials = %d, want %d", dials, tc.wantDials)
			}
			if !slices.Equal(slept, tc.wantSleep) {
				t.Errorf("backoff = %v, want %v", slept, tc.wantSleep)
			}
			if tc.wantErr == nil && err != nil {
				t.Errorf("err = %v, want nil", err)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Errorf("err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// fakePostgres stands in for crt.sh's pooler. A client that connects gets
// startupErr, or logs in when it is nil. A query then gets queryErr, or no answer
// at all when it is nil, like a statement stuck in the pool's queue.
func fakePostgres(t *testing.T, startupErr, queryErr *pgproto3.ErrorResponse) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				be := pgproto3.NewBackend(c, c)
				if _, err := be.ReceiveStartupMessage(); err != nil {
					return
				}
				if startupErr != nil {
					be.Send(startupErr)
					be.Flush()
					return
				}
				be.Send(&pgproto3.AuthenticationOk{})
				// pgx refuses simple protocol queries without these.
				be.Send(&pgproto3.ParameterStatus{Name: "standard_conforming_strings", Value: "on"})
				be.Send(&pgproto3.ParameterStatus{Name: "client_encoding", Value: "UTF8"})
				be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
				be.Flush()
				for {
					msg, err := be.Receive()
					if err != nil {
						return
					}
					if _, ok := msg.(*pgproto3.Query); ok && queryErr != nil {
						be.Send(queryErr)
						be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
						be.Flush()
					}
				}
			}()
		}
	}()
	return l.Addr().String()
}

// searchFake runs CrtShDB's connect and query against addr and wraps errors the
// way CrtShDB.Search and connect do, so the error chain is the real one.
func searchFake(t *testing.T, addr string, timeout time.Duration) error {
	t.Helper()
	host, port, _ := net.SplitHostPort(addr)
	cfg, err := pgx.ParseConfig("host=" + host + " port=" + port + " user=guest dbname=certwatch sslmode=disable connect_timeout=1")
	if err != nil {
		t.Fatal(err)
	}
	cfg.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return fmt.Errorf("crt.sh db: giving up after 5 attempts: %w", err)
	}
	defer conn.Close(context.Background())
	rows, err := conn.Query(ctx, crtshDBQuery, "example.com")
	if err != nil {
		return fmt.Errorf("crt.sh db: %w", err)
	}
	for rows.Next() {
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("crt.sh db: %w", err)
	}
	t.Fatal("query succeeded")
	return nil
}

func TestCrtShDBOverloaded(t *testing.T) {
	pgErr := func(code, msg string) *pgproto3.ErrorResponse {
		return &pgproto3.ErrorResponse{Severity: "FATAL", Code: code, Message: msg}
	}
	closedPort := func(t *testing.T) string {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		l.Close()
		return l.Addr().String()
	}
	silentPort := func(t *testing.T) string {
		// Accepts and never answers, like a firewall that drops packets after the handshake.
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { l.Close() })
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				defer c.Close()
			}
		}()
		return l.Addr().String()
	}

	tests := []struct {
		name       string
		err        func(t *testing.T) error
		overloaded bool
	}{
		// Server side: crt.sh answered, so the JSON API would hit the same wall.
		{"pool full", func(t *testing.T) error {
			return searchFake(t, fakePostgres(t, pgErr("08P01", "no more connections allowed (max_client_conn)"), nil), 5*time.Second)
		}, true},
		{"too many connections", func(t *testing.T) error {
			return searchFake(t, fakePostgres(t, pgErr("53300", "sorry, too many clients already"), nil), 5*time.Second)
		}, true},
		{"statement timeout", func(t *testing.T) error {
			return searchFake(t, fakePostgres(t, nil, pgErr("57014", "canceling statement due to statement timeout")), 5*time.Second)
		}, true},
		{"query still queued at the deadline", func(t *testing.T) error {
			return searchFake(t, fakePostgres(t, nil, nil), 300*time.Millisecond)
		}, true},

		// Network level or not about load: the API on port 443 may still answer.
		{"port refused", func(t *testing.T) error { return searchFake(t, closedPort(t), 5*time.Second) }, false},
		{"dial timeout", func(t *testing.T) error { return searchFake(t, silentPort(t), 5*time.Second) }, false},
		{"tls verification", func(*testing.T) error {
			return fmt.Errorf("crt.sh db: %w", &tls.CertificateVerificationError{Err: errors.New("bad chain")})
		}, false},
		{"schema changed", func(t *testing.T) error {
			return searchFake(t, fakePostgres(t, nil, pgErr("42P01", `relation "certificate" does not exist`)), 5*time.Second)
		}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.err(t)
			reason, ok := CrtShDB{}.overloaded(err)
			if ok != tt.overloaded {
				t.Fatalf("overloaded = %v (%q), want %v: %v", ok, reason, tt.overloaded, err)
			}
			if ok && reason == "" {
				t.Error("no reason given")
			}
		})
	}
}

func TestCrtShDBConnectCancelInterruptsBackoff(t *testing.T) {
	refused := errors.New("connection refused")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dials := 0
	s := CrtShDB{
		Retries: 4,
		Backoff: time.Hour,
		dial: func(context.Context, *pgx.ConnConfig) (*pgx.Conn, error) {
			dials++
			return nil, refused
		},
		after: func(time.Duration) <-chan time.Time {
			cancel()   // the caller gives up while the loop waits
			return nil // never fires: only ctx.Done can end the wait
		},
	}
	done := make(chan error, 1)
	go func() {
		_, err := s.connect(ctx)
		done <- err
	}()
	select {
	case err := <-done:
		// Cancelled, not refused: callers treat Ctrl-C as a clean exit.
		if !errors.Is(err, context.Canceled) || !errors.Is(err, refused) || !strings.Contains(err.Error(), refused.Error()) {
			t.Errorf("err = %v, want %v and %v", err, context.Canceled, refused)
		}
		if dials != 1 {
			t.Errorf("dials = %d, want 1", dials)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancellation did not interrupt the backoff")
	}
}

func TestCrtShDBConnectStopsWhenOutOfTime(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	dials := 0
	s := CrtShDB{
		Retries: 4,
		Backoff: time.Second,
		dial: func(context.Context, *pgx.ConnConfig) (*pgx.Conn, error) {
			dials++
			cancel() // the deadline passes during the dial
			return nil, errors.New("connection refused")
		},
		after: func(time.Duration) <-chan time.Time {
			t.Fatal("backed off after the context ended")
			return nil
		},
	}
	if _, err := s.connect(ctx); err == nil {
		t.Fatal("connected")
	}
	if dials != 1 {
		t.Errorf("dials = %d, want 1", dials)
	}
}

func TestScopeDBCertsSanitizes(t *testing.T) {
	// crt.sh's own parser fills issuer for rows Go rejects, unescaped.
	now := time.Now()
	row := dbCert{id: 1, key: "k", issuer: "CN=\x1b[2J", names: []string{"\x1b]0;evil\x07.example.com"}, notBefore: now, notAfter: now.Add(time.Hour)}
	certs := scopeDBCerts([]dbCert{row}, "example.com", true, false, now)
	if len(certs) != 1 || certs[0].Issuer != `CN=\x1b[2J` || !slices.Equal(certs[0].DNSNames, []string{`\x1b]0;evil\x07.example.com`}) {
		t.Errorf("certs = %q", certs)
	}
}
