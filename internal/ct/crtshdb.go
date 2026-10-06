package ct

import (
	"cmp"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
)

// CrtShDB queries crt.sh's public Postgres directly. It returns the full history
// in one statement, where the JSON API times out on large domains. The guest pool
// is shared and every statement waits in its queue (often 45s or more), so the
// timeout covers the whole search and needs minutes, not seconds.
type CrtShDB struct {
	Timeout time.Duration // connect, queue and query together
	Retries int           // reconnects when the pool refuses clients
	Backoff time.Duration
	Warn    io.Writer
}

func (CrtShDB) Name() string { return "crtsh-db" }

const crtshDBHost = "crt.sh"

// The certwatch text search config indexes every name in a certificate, so this
// uses the per-partition GIN indexes. Only the DER comes back: parsing it here
// keeps the dependency on crt.sh's undocumented schema to one table and one function.
const crtshDBQuery = `SELECT c.id, c.certificate FROM certificate c WHERE plainto_tsquery('certwatch', $1) @@ identities(c.certificate)`

type dbRow struct {
	id  int64
	der []byte
}

func (s CrtShDB) Search(ctx context.Context, domain string, subdomains, includeExpired bool) ([]Certificate, error) {
	if s.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.Timeout)
		defer cancel()
	}
	conn, err := s.connect(ctx)
	if err != nil {
		return nil, fmt.Errorf("crt.sh db: %w", err)
	}
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn.Close(closeCtx)
	}()

	rows, err := conn.Query(ctx, crtshDBQuery, domain)
	if err != nil {
		return nil, fmt.Errorf("crt.sh db: %w", err)
	}
	var raw []dbRow
	for rows.Next() {
		var r dbRow
		if err := rows.Scan(&r.id, &r.der); err != nil {
			rows.Close()
			return nil, fmt.Errorf("crt.sh db: %w", err)
		}
		raw = append(raw, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("crt.sh db: %w", err)
	}

	certs, skipped := fromDBRows(raw, domain, subdomains, includeExpired, time.Now())
	if skipped > 0 {
		warnf(s.Warn, "crt.sh db: skipped %d certificates that could not be parsed", skipped)
	}
	return certs, nil
}

func (s CrtShDB) connect(ctx context.Context) (*pgx.Conn, error) {
	cfg, err := crtshDBConfig()
	if err != nil {
		return nil, err
	}
	var last error
	timeouts := 0
	for attempt := 0; attempt <= s.Retries; attempt++ {
		conn, err := pgx.ConnectConfig(ctx, cfg)
		if err == nil {
			return conn, nil
		}
		kind := classifyConnErr(err)
		if kind == connTimeout {
			timeouts++
		}
		if ctx.Err() != nil || kind == connFatal || timeouts > 1 {
			return nil, err
		}
		last = err
		if attempt == s.Retries {
			break
		}
		select {
		case <-ctx.Done():
			return nil, last
		case <-time.After(s.Backoff << attempt):
		}
	}
	return nil, fmt.Errorf("giving up after %d attempts: %w", s.Retries+1, last)
}

type connErrKind int

const (
	connRetry   connErrKind = iota // refused, or "no more connections allowed (max_client_conn)"
	connTimeout                    // dial or handshake timed out
	connFatal                      // TLS verification failed: retrying can't help
)

// classifyConnErr sorts connection failures for the retry loop. crt.sh refuses
// connections and stops answering SYNs for seconds at a time. A timeout looks
// the same as a firewall dropping port 5432, so it gets one retry and no more:
// on a blocked network that costs one extra connect_timeout before falling back.
func classifyConnErr(err error) connErrKind {
	var tlsErr *tls.CertificateVerificationError
	if errors.As(err, &tlsErr) {
		return connFatal
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return connTimeout
	}
	return connRetry
}

// crtshDBConfig pins every connection setting. pgx.ParseConfig always merges PG*
// variables and service files, so everything that matters is overridden after
// parsing and the environment can't redirect or downgrade the connection.
// sslmode=disable and an empty sslrootcert only stop pgx from building its own TLS
// config and reading PGSSLROOTCERT: TLSConfig is set below, and pgx uses whatever is there.
// target_session_attrs=any keeps a PGTARGETSESSIONATTRS from adding a validation
// query, which would wait in the pool's queue a second time.
func crtshDBConfig() (*pgx.ConnConfig, error) {
	cfg, err := pgx.ParseConfig("host=" + crtshDBHost + " port=5432 user=guest dbname=certwatch connect_timeout=15" +
		" sslmode=disable sslrootcert='' sslnegotiation=postgres target_session_attrs=any")
	if err != nil {
		return nil, err
	}
	cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.Database = crtshDBHost, 5432, "guest", "", "certwatch"
	cfg.Fallbacks = nil
	cfg.ValidateConnect, cfg.AfterConnect = nil, nil
	cfg.TLSConfig = &tls.Config{
		ServerName: crtshDBHost,
		MinVersion: tls.VersionTLS12,
		// Not a skip: VerifyConnection below does the full chain and hostname check.
		InsecureSkipVerify: true,
		VerifyConnection:   verifyWithExpiredPin(crtshDBHost, nil, crtshDBExpiredKeyPin),
	}
	cfg.RuntimeParams = map[string]string{"application_name": UserAgent}
	// crt.sh sits behind a connection pooler, which breaks named prepared statements.
	cfg.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	return cfg, nil
}

// crtshDBExpiredKeyPin is the SHA-256 of the public key (SPKI) that crt.sh serves
// on port 5432. Its certificate there expired on 2026-06-21; crt.sh's HTTPS
// certificate, valid until 2026-12-21, uses the same key.
const crtshDBExpiredKeyPin = "f5178a69c95d4f2a114aa431ffd770905b87755f0c4f231675c2847f6a21ebda"

// verifyWithExpiredPin verifies the chain to roots (nil means the system pool) and
// the hostname. If that fails only because the leaf has expired, and the leaf's
// key matches pin, the chain is verified again at the leaf's last valid second.
// Any other expired certificate for host is rejected: the exception covers one
// key, not every crt.sh certificate ever issued. Once crt.sh renews, the strict
// check passes and the pin is unused.
func verifyWithExpiredPin(host string, roots *x509.CertPool, pin string) func(tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("server sent no certificate")
		}
		leaf := cs.PeerCertificates[0]
		opts := x509.VerifyOptions{DNSName: host, Roots: roots, Intermediates: x509.NewCertPool()}
		for _, c := range cs.PeerCertificates[1:] {
			opts.Intermediates.AddCert(c)
		}
		_, err := leaf.Verify(opts)
		if err != nil && time.Now().After(leaf.NotAfter) && spkiSHA256(leaf) == pin {
			// x509.Expired also means "not yet valid", hence the explicit date check above.
			opts.CurrentTime = leaf.NotAfter
			_, err = leaf.Verify(opts)
		}
		if err != nil {
			// crypto/tls only wraps its built-in verification; wrap here so callers can tell.
			return &tls.CertificateVerificationError{UnverifiedCertificates: cs.PeerCertificates, Err: err}
		}
		return nil
	}
}

func spkiSHA256(c *x509.Certificate) string {
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// fromDBRows parses and scopes rows. crt.sh stores a precertificate and its final
// certificate as two rows; like the JSON API's deduplicate=Y, only the first by id
// is kept per issuer and serial. skipped counts DER that Go refuses to parse.
func fromDBRows(rows []dbRow, domain string, subdomains, includeExpired bool, now time.Time) (certs []Certificate, skipped int) {
	slices.SortFunc(rows, func(a, b dbRow) int { return cmp.Compare(a.id, b.id) })
	seen := make(map[string]bool, len(rows))
	for _, r := range rows {
		x, err := x509.ParseCertificate(r.der)
		if err != nil {
			skipped++
			continue
		}
		key := string(x.RawIssuer) + "/" + x.SerialNumber.String()
		if seen[key] {
			continue
		}
		seen[key] = true
		c, ok := fromX509(strconv.FormatInt(r.id, 10), "crtsh-db", x, domain, subdomains)
		if !ok || (!includeExpired && c.Expired(now)) {
			continue
		}
		certs = append(certs, c)
	}
	return certs, skipped
}
