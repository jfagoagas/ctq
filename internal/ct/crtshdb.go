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
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
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

	// Tests replace these; nil means pgx.ConnectConfig and time.After.
	dial  func(context.Context, *pgx.ConnConfig) (*pgx.Conn, error)
	after func(time.Duration) <-chan time.Time
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
	ctx = withSource(ctx, s.Name())
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

	Trace(ctx, LevelInfo, "query sent; crt.sh's shared pool queues it (often 45s or more), then it runs")
	start := time.Now()
	rows, err := conn.Query(ctx, crtshDBQuery, domain)
	if err != nil {
		Trace(ctx, LevelError, "query failed after %s: %v", since(start), err)
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
		Trace(ctx, LevelError, "query failed after %s: %v", since(start), err)
		return nil, fmt.Errorf("crt.sh db: %w", err)
	}
	Trace(ctx, LevelInfo, "%d rows in %s", len(raw), since(start))

	certs, skipped := fromDBRows(raw, domain, subdomains, includeExpired, time.Now())
	if skipped > 0 {
		searchWarnf(ctx, s.Warn, "crt.sh db: skipped %d certificates that could not be parsed", skipped)
	}
	Trace(ctx, LevelInfo, "%d certificates after removing precertificate duplicates and out-of-scope rows", len(certs))
	return certs, nil
}

func (s CrtShDB) connect(ctx context.Context) (*pgx.Conn, error) {
	cfg, err := crtshDBConfig()
	if err != nil {
		return nil, err
	}
	dial, after := s.dial, s.after
	if dial == nil {
		dial = pgx.ConnectConfig
	}
	if after == nil {
		after = time.After
	}
	var last error
	timeouts := 0
	for attempt := 0; attempt <= s.Retries; attempt++ {
		Trace(ctx, LevelInfo, "connecting to %s:5432 (attempt %d of %d)", crtshDBHost, attempt+1, s.Retries+1)
		start := time.Now()
		conn, err := dial(ctx, cfg)
		if err == nil {
			Trace(ctx, LevelInfo, "connected in %s", since(start))
			return conn, nil
		}
		kind := classifyConnErr(err)
		if kind == connTimeout {
			timeouts++
		}
		switch {
		case ctx.Err() != nil:
			Trace(ctx, LevelError, "attempt %d failed after %s: %v; out of time", attempt+1, since(start), err)
			return nil, err
		case kind == connFatal:
			Trace(ctx, LevelError, "attempt %d failed: %v; TLS verification failures are not retried", attempt+1, err)
			return nil, err
		case timeouts > 1:
			Trace(ctx, LevelError, "attempt %d timed out after %s: %v; second timeout, port 5432 may be blocked on this network", attempt+1, since(start), err)
			return nil, err
		}
		last = err
		if attempt == s.Retries {
			Trace(ctx, LevelError, "attempt %d failed after %s: %v; no retries left", attempt+1, since(start), err)
			break
		}
		delay := s.Backoff << attempt
		Trace(ctx, LevelWarn, "attempt %d failed after %s: %v; retrying in %s", attempt+1, since(start), err, delay)
		select {
		case <-ctx.Done():
			return nil, last
		case <-after(delay):
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

// backend is crt.sh's database, which the JSON API (CrtSh) queries too.
func (CrtShDB) backend() string { return crtshDBHost }

// overloaded reports whether err shows that crt.sh itself gave up: its pooler or
// Postgres answered with an error, or the query was accepted and still had no
// answer when the timeout expired. The JSON API runs on the same database, so it
// would fail the same way. A refused or silent port 5432 and TLS failures are not
// overload: they can be this network, and the API on port 443 may still answer.
func (CrtShDB) overloaded(err error) (reason string, ok bool) {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch {
		case pgErr.Code == "57014": // query_canceled: statement_timeout
			return "crt.sh cancelled the query: " + pgErr.Message, true
		case pgErr.Code == "08P01", // PgBouncer's code for max_client_conn, query_wait_timeout and the like
			strings.HasPrefix(pgErr.Code, "53"),                                 // insufficient_resources, including too_many_connections
			pgErr.Code == "57P01", pgErr.Code == "57P02", pgErr.Code == "57P03": // shutting down or starting up
			return "crt.sh refused the work: " + pgErr.Message, true
		}
		return "", false
	}
	var connErr *pgconn.ConnectError
	if !errors.As(err, &connErr) && classifyConnErr(err) == connTimeout {
		// Connected, so port 5432 is reachable: the time went to crt.sh's queue or the query.
		return "the query got no answer before the timeout", true
	}
	return "", false
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
		InsecureSkipVerify: true, //nolint:gosec // G402: VerifyConnection verifies chain, hostname and the expired-key pin (#9)
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
