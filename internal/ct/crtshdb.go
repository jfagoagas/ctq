package ct

import (
	"cmp"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
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
	// Zero means crtshDBMaxRows and crtshDBMaxBytes.
	maxRows, maxBytes int
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

// Caps on what one search holds in memory. The HTTP client stops at 64 MiB; rows
// here are kept as DER and parsed after the scan, so the cap is on that. A
// certificate is 1-2 KiB of DER, and busy domains with years of history have tens
// of thousands of rows, so 500k rows or 256 MiB leaves an order of magnitude of
// headroom. Shared hosting suffixes (github.io, herokuapp.com) have millions.
const (
	crtshDBMaxRows  = 500_000
	crtshDBMaxBytes = 256 << 20
)

// rowScanner is the part of pgx.Rows that collectRows uses.
type rowScanner interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
}

// collectRows reads (id, DER) rows and fails as soon as either cap is passed,
// leaving the caller to stop the query. Zero caps mean the defaults.
func collectRows(rows rowScanner, maxRows, maxBytes int) ([]dbRow, error) {
	maxRows, maxBytes = cmp.Or(maxRows, crtshDBMaxRows), cmp.Or(maxBytes, crtshDBMaxBytes)
	var raw []dbRow
	size := 0
	for rows.Next() {
		var r dbRow
		if err := rows.Scan(&r.id, &r.der); err != nil {
			return nil, err
		}
		size += len(r.der)
		if len(raw) == maxRows || size > maxBytes {
			return nil, fmt.Errorf("more than %d certificates or %d MiB match; search a narrower domain, or use -source certspotter", maxRows, maxBytes>>20)
		}
		raw = append(raw, r)
	}
	return raw, rows.Err()
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
	qctx, stopQuery := context.WithCancel(ctx)
	defer stopQuery()
	rows, err := conn.Query(qctx, crtshDBQuery, domain)
	if err != nil {
		Trace(ctx, LevelError, "query failed after %s: %v", since(start), err)
		return nil, fmt.Errorf("crt.sh db: %w", err)
	}
	raw, err := collectRows(rows, s.maxRows, s.maxBytes)
	if err != nil {
		// pgx's Close reads the remaining rows; cancelling first drops the connection instead.
		stopQuery()
		rows.Close()
		Trace(ctx, LevelError, "query failed after %s: %v", since(start), err)
		return nil, fmt.Errorf("crt.sh db: %w", err)
	}
	Trace(ctx, LevelInfo, "%d rows in %s", len(raw), since(start))

	parsed, failed := parseDBRows(ctx, raw)
	skipped := len(failed)
	if len(failed) > 0 {
		Trace(ctx, LevelInfo, "asking crt.sh's parser for the %d rows Go rejected; the statement queues again", len(failed))
		start := time.Now()
		read, err := readUnparsed(ctx, conn, failed)
		if err != nil {
			Trace(ctx, LevelWarn, "fallback query failed after %s: %v", since(start), err)
		} else {
			Trace(ctx, LevelInfo, "crt.sh read %d of %d rejected rows in %s", len(read), len(failed), since(start))
			parsed = append(parsed, read...)
			skipped -= len(read)
		}
	}

	certs := scopeDBCerts(parsed, domain, subdomains, includeExpired, time.Now())
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
			// Report why it stopped first: Ctrl-C is not a refused connection.
			return nil, fmt.Errorf("%w (last attempt: %w)", context.Cause(ctx), last)
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
		VerifyConnection:   verifyWithExpiredPin(crtshDBHost, nil, crtshDBExpiredKeyPin, crtshDBPinUntil, nil),
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

// crtshDBPinUntil ends the exception: the HTTPS certificate with the pinned key
// expires at this instant, and after it the key has no valid certificate anywhere.
var crtshDBPinUntil = time.Date(2026, 12, 21, 23, 59, 59, 0, time.UTC)

// verifyWithExpiredPin verifies the chain to roots (nil means the system pool) and
// the hostname. If that fails only because the leaf has expired, and the leaf's
// key matches pin, the chain is verified again at the leaf's last valid second.
// Any other expired certificate for host is rejected: the exception covers one
// key, not every crt.sh certificate ever issued. Once crt.sh renews, the strict
// check passes and the pin is unused. After until the exception ends and the
// connection fails closed. now is the clock; nil means time.Now.
func verifyWithExpiredPin(host string, roots *x509.CertPool, pin string, until time.Time, now func() time.Time) func(tls.ConnectionState) error {
	if now == nil {
		now = time.Now
	}
	return func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("server sent no certificate")
		}
		leaf := cs.PeerCertificates[0]
		t := now()
		opts := x509.VerifyOptions{DNSName: host, Roots: roots, Intermediates: x509.NewCertPool(), CurrentTime: t}
		for _, c := range cs.PeerCertificates[1:] {
			opts.Intermediates.AddCert(c)
		}
		_, err := leaf.Verify(opts)
		// x509.Expired also means "not yet valid", hence the explicit date check.
		if err != nil && t.After(leaf.NotAfter) && spkiSHA256(leaf) == pin {
			if t.After(until) {
				err = fmt.Errorf("the exception for %s's expired certificate ended on %s and %s still serves it; see https://github.com/jfagoagas/ctq/issues/9: %w",
					host, until.Format(time.DateOnly), host, err)
			} else {
				opts.CurrentTime = leaf.NotAfter
				_, err = leaf.Verify(opts)
			}
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

// dbCert is one row as read by Go's parser or by crt.sh's, before deduplication and scoping.
type dbCert struct {
	id                  int64
	key                 string // issuer and serial, see dbKey
	issuer              string
	names               []string // SANs and subject CN, unscoped
	notBefore, notAfter time.Time
}

// dbKey identifies a certificate across rows: a precertificate and its final
// certificate share it, and so do copies whose outer signature was tampered with.
func dbKey(rawIssuer []byte, serial *big.Int) string {
	return string(rawIssuer) + "/" + serial.String()
}

// parseDBRows parses the DER of each row. Rows Go rejects are returned in failed
// for readUnparsed. Go is stricter than CAs have been (malformed strings and
// extensions, negative serials, mismatched signature algorithms), and crt.sh logs it all.
func parseDBRows(ctx context.Context, rows []dbRow) (certs []dbCert, failed []int64) {
	for _, r := range rows {
		x, err := x509.ParseCertificate(r.der)
		if err != nil {
			Trace(ctx, LevelWarn, "crt.sh id %d: %v", r.id, err)
			failed = append(failed, r.id)
			continue
		}
		certs = append(certs, dbCert{
			id:        r.id,
			key:       dbKey(x.RawIssuer, x.SerialNumber),
			issuer:    x.Issuer.String(),
			names:     slices.Concat(x.DNSNames, []string{x.Subject.CommonName}),
			notBefore: x.NotBefore,
			notAfter:  x.NotAfter,
		})
	}
	return certs, failed
}

// crtshDBFallbackQuery reads rows Go rejects with crt.sh's own parser (OpenSSL,
// through libx509pq), which also feeds the JSON API. x509_name(..., FALSE) is the
// issuer DER and x509_serialNumber the serial's bytes: the same values as Go's
// RawIssuer and SerialNumber, so these rows deduplicate against parsed ones.
// Type 2 is GEN_DNS. $1 is cast because the simple protocol sends it as text.
const crtshDBFallbackQuery = `SELECT c.id, x509_name(c.certificate, FALSE), x509_issuerName(c.certificate),
	x509_serialNumber(c.certificate), x509_notBefore(c.certificate), x509_notAfter(c.certificate),
	array_remove(ARRAY(SELECT x509_altNames(c.certificate, 2)) || x509_commonName(c.certificate), NULL)
FROM certificate c WHERE c.id = ANY($1::bigint[])`

type dbFallbackRow struct {
	id                  int64
	issuerDER, serial   []byte
	issuerName          *string
	notBefore, notAfter *time.Time
	names               []string
}

// readUnparsed asks crt.sh for the names and dates of the rows in ids. It is a
// second statement, so it waits in the pool's queue again; it only runs when Go
// rejected something. Rows crt.sh can't read either are left out.
func readUnparsed(ctx context.Context, conn *pgx.Conn, ids []int64) ([]dbCert, error) {
	rows, err := conn.Query(ctx, crtshDBFallbackQuery, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var certs []dbCert
	for rows.Next() {
		var r dbFallbackRow
		if err := rows.Scan(&r.id, &r.issuerDER, &r.issuerName, &r.serial, &r.notBefore, &r.notAfter, &r.names); err != nil {
			return nil, err
		}
		if c, ok := r.cert(); ok {
			certs = append(certs, c)
		} else {
			Trace(ctx, LevelWarn, "crt.sh id %d: crt.sh's parser can't read it either", r.id)
		}
	}
	return certs, rows.Err()
}

func (r dbFallbackRow) cert() (dbCert, bool) {
	if len(r.issuerDER) == 0 || len(r.serial) == 0 || r.notBefore == nil || r.notAfter == nil {
		return dbCert{}, false
	}
	// Format the issuer the way Go does for parsed rows; crt.sh's own text is the fallback.
	var issuer string
	var rdn pkix.RDNSequence
	if rest, err := asn1.Unmarshal(r.issuerDER, &rdn); err == nil && len(rest) == 0 {
		var n pkix.Name
		n.FillFromRDNSequence(&rdn)
		issuer = n.String()
	} else if r.issuerName != nil {
		issuer = *r.issuerName
	}
	return dbCert{
		id: r.id,
		// Go rejects negative serials, so only these rows can have one and
		// reading the bytes as unsigned keeps their keys consistent.
		key:       dbKey(r.issuerDER, new(big.Int).SetBytes(r.serial)),
		issuer:    issuer,
		names:     r.names,
		notBefore: *r.notBefore,
		notAfter:  *r.notAfter,
	}, true
}

// scopeDBCerts deduplicates and scopes rows. crt.sh stores a precertificate and
// its final certificate as two rows; like the JSON API's deduplicate=Y, only the
// first by id is kept per issuer and serial.
func scopeDBCerts(rows []dbCert, domain string, subdomains, includeExpired bool, now time.Time) []Certificate {
	slices.SortFunc(rows, func(a, b dbCert) int { return cmp.Compare(a.id, b.id) })
	seen := make(map[string]bool, len(rows))
	var certs []Certificate
	for _, r := range rows {
		if seen[r.key] {
			continue
		}
		seen[r.key] = true
		names := Scope(r.names, domain, subdomains)
		if len(names) == 0 {
			continue
		}
		c := Certificate{
			ID:        strconv.FormatInt(r.id, 10),
			Source:    "crtsh-db",
			Issuer:    sanitize(r.issuer),
			DNSNames:  names,
			NotBefore: r.notBefore.UTC(),
			NotAfter:  r.notAfter.UTC(),
		}
		if !includeExpired && c.Expired(now) {
			continue
		}
		certs = append(certs, c)
	}
	return certs
}
