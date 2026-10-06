// Command ctq queries Certificate Transparency for a domain.
//
//	ctq search [flags] <domain>   historical certs via crt.sh / Cert Spotter
//	ctq watch  [flags] <domain>   new certs, read straight from the CT logs
//	ctq tui    [flags] <domain>   interactive view over both
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/jfagoagas/ctq/internal/ct"
	"github.com/jfagoagas/ctq/internal/tui"
)

const usage = `ctq: query Certificate Transparency for a domain

Usage:
  ctq search [flags] <domain>   certificates already logged (crt.sh, Cert Spotter)
  ctq watch  [flags] <domain>   new certificates, tailed directly from all CT logs
  ctq tui    [flags] [domain]   interactive: history, live feed and subdomain inventory
  ctq version                   print the version

Run "ctq <command> -h" for flags.
`

// Test seams: tests point these at local fakes instead of the real services.
var (
	searcherFor = newSearcher
	fetchLogs   = ct.FetchLogs
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	ct.UserAgent = "ctq/" + buildVersion()
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

// run executes one ctq command and returns the process exit code:
// 0 on success, 1 when the command fails, 2 for a missing or unknown command.
func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	var err error
	switch args[0] {
	case "search":
		err = runSearch(ctx, args[1:], stdout, stderr)
	case "watch":
		err = runWatch(ctx, args[1:], stdout, stderr)
	case "tui":
		err = runTUI(ctx, args[1:], stderr)
	case "-h", "-help", "--help", "help":
		fmt.Fprint(stdout, usage)
		return 0
	case "version", "-version", "--version":
		fmt.Fprintln(stdout, versionString())
		return 0
	default:
		fmt.Fprintf(stderr, "ctq: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
	if err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintf(stderr, "ctq: %v\n", err)
		return 1
	}
	return 0
}

func parseArgs(fs *flag.FlagSet, args []string) (string, error) {
	if err := fs.Parse(args); err != nil {
		return "", err
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return "", errors.New("expected exactly one domain")
	}
	return ct.NormalizeDomain(fs.Arg(0))
}

func runSearch(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("search", flag.ContinueOnError)
	fs.SetOutput(stderr)
	source := fs.String("source", "auto", "auto | crtsh-db | crtsh | certspotter")
	output := fs.String("o", "names", "names | table | json")
	exact := fs.Bool("exact", false, "only the domain itself, no subdomains")
	expired := fs.Bool("expired", false, "include expired certificates (crt.sh sources only)")
	issuer := fs.String("issuer", "", "only certs whose issuer contains this (case-insensitive)")
	timeout := fs.Duration("timeout", 60*time.Second, "per-request timeout")
	verbose := fs.Bool("v", false, "print each source's connections, requests, retries and fallbacks to stderr")
	domain, err := parseArgs(fs, args)
	if err != nil {
		return err
	}

	s, err := searcherFor(*source, *timeout, stderr)
	if err != nil {
		return err
	}
	if *verbose {
		ctx = ct.WithTracer(ctx, func(source string, level ct.Level, msg string) {
			fmt.Fprintf(stderr, "%s %-11s %s%s\n", time.Now().Format("15:04:05"), source, [...]string{"", "warning: ", "error: "}[level], msg)
		})
	}
	certs, err := s.Search(ctx, domain, !*exact, *expired)
	if err != nil {
		return err
	}
	if *issuer != "" {
		needle := strings.ToLower(*issuer)
		kept := certs[:0]
		for _, c := range certs {
			if strings.Contains(strings.ToLower(c.Issuer), needle) {
				kept = append(kept, c)
			}
		}
		certs = kept
	}
	sort.Slice(certs, func(i, j int) bool { return certs[i].NotBefore.After(certs[j].NotBefore) })
	return writeSearch(stdout, *output, certs, time.Now())
}

func newSearcher(source string, timeout time.Duration, warn io.Writer) (ct.Searcher, error) {
	spotter := ct.CertSpotter{Client: ct.NewClient(timeout, 2), APIKey: os.Getenv("CERTSPOTTER_API_KEY"), Warn: warn}
	// The guest pool queues every statement for about a minute before running it, and
	// crt.sh often refuses connections for tens of seconds: 4 retries back off for 75s.
	db := ct.CrtShDB{Timeout: max(timeout, 3*time.Minute), Retries: 4, Backoff: 5 * time.Second, Warn: warn}
	switch source {
	case "crtsh-db":
		return db, nil
	case "crtsh":
		return ct.CrtSh{Client: ct.NewClient(timeout, 3)}, nil
	case "certspotter":
		return spotter, nil
	case "auto":
		// Short leash on the crt.sh API: when its DB is overloaded, minutes of retries only delay the fallback.
		// It stays in the chain for networks that block port 5432.
		web := ct.CrtSh{Client: ct.NewClient(min(timeout, 30*time.Second), 1)}
		return ct.Auto{Sources: []ct.Searcher{db, web, spotter}, Warn: warn}, nil
	}
	return nil, fmt.Errorf("unknown source %q", source)
}

func writeSearch(w io.Writer, format string, certs []ct.Certificate, now time.Time) error {
	switch format {
	case "names":
		seen := map[string]struct{}{}
		var names []string
		for _, c := range certs {
			for _, n := range c.DNSNames {
				if _, ok := seen[n]; !ok {
					seen[n] = struct{}{}
					names = append(names, n)
				}
			}
		}
		sort.Strings(names)
		for _, n := range names {
			fmt.Fprintln(w, n)
		}
	case "table":
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "NOT BEFORE\tNOT AFTER\tSTATUS\tISSUER\tNAMES")
		for _, c := range certs {
			status := "valid"
			if c.Expired(now) {
				status = "expired"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", c.NotBefore.Format("2006-01-02"), c.NotAfter.Format("2006-01-02"),
				status, ct.IssuerCN(c.Issuer), strings.Join(c.DNSNames, ","))
		}
		return tw.Flush()
	case "json":
		type row struct {
			ct.Certificate
			Expired bool `json:"expired"`
		}
		rows := make([]row, len(certs))
		for i, c := range certs {
			rows[i] = row{c, c.Expired(now)}
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(rows)
	default:
		return fmt.Errorf("unknown output %q", format)
	}
	return nil
}

func runWatch(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("watch", flag.ContinueOnError)
	fs.SetOutput(stderr)
	exact := fs.Bool("exact", false, "only the domain itself, no subdomains")
	interval := fs.Duration("interval", 15*time.Second, "poll interval per log")
	workers := fs.Int("workers", 4, "concurrent fetches per log")
	statePath := fs.String("state", "", "file to persist log offsets; resumes from it on restart")
	logFilter := fs.String("log", "", "only logs whose name contains this (case-insensitive)")
	asJSON := fs.Bool("json", false, "emit JSON lines")
	verbose := fs.Bool("v", false, "log progress and lag per log to stderr")
	domain, err := parseArgs(fs, args)
	if err != nil {
		return err
	}

	w, err := newWatcher(ctx, watchConfig{
		domain: domain, subdomains: !*exact, interval: *interval, workers: *workers,
		statePath: *statePath, logFilter: *logFilter, warn: stderr,
	})
	if err != nil {
		return err
	}
	tiled := 0
	for _, l := range w.Logs {
		if l.Tiled {
			tiled++
		}
	}
	fmt.Fprintf(stderr, "ctq: watching %d logs (%d tiled) for %s, Ctrl-C to stop\n", len(w.Logs), tiled, domain)

	enc := json.NewEncoder(stdout)
	w.Verbose = *verbose
	w.Emit = func(m ct.Match) {
		if *asJSON {
			enc.Encode(m)
			return
		}
		kind := "cert   "
		if m.Precert {
			kind = "precert"
		}
		fmt.Fprintf(stdout, "%s  %s  %-24s  %s  [%s]\n", time.Now().UTC().Format(time.RFC3339), kind,
			ct.IssuerCN(m.Issuer), strings.Join(m.DNSNames, ","), m.Log)
	}
	return w.Run(ctx)
}

type watchConfig struct {
	domain     string
	subdomains bool
	interval   time.Duration
	workers    int
	statePath  string
	logFilter  string
	warn       io.Writer
}

// newWatcher fetches the log list and loads saved offsets. The caller sets Emit.
func newWatcher(ctx context.Context, c watchConfig) (*ct.Watcher, error) {
	client := ct.NewClient(30*time.Second, 3)
	logs, err := fetchLogs(ctx, client, time.Now())
	if err != nil {
		return nil, err
	}
	if c.logFilter != "" {
		needle := strings.ToLower(c.logFilter)
		kept := logs[:0]
		for _, l := range logs {
			if strings.Contains(strings.ToLower(l.Name), needle) {
				kept = append(kept, l)
			}
		}
		logs = kept
	}
	if len(logs) == 0 {
		return nil, errors.New("no logs to watch")
	}
	state, err := ct.LoadState(c.statePath)
	if err != nil {
		return nil, err
	}
	return &ct.Watcher{
		Logs:       logs,
		NewReader:  func(l ct.Log) ct.LogReader { return ct.NewReader(client, l) },
		Domain:     c.domain,
		Subdomains: c.subdomains,
		Interval:   c.interval,
		Workers:    c.workers,
		State:      state,
		Warn:       c.warn,
	}, nil
}

func runTUI(ctx context.Context, args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("tui", flag.ContinueOnError)
	fs.SetOutput(stderr)
	source := fs.String("source", "auto", "auto | crtsh-db | crtsh | certspotter (press s to cycle)")
	exact := fs.Bool("exact", false, "only the domain itself, no subdomains")
	expired := fs.Bool("expired", false, "include expired certificates in history (crt.sh sources only)")
	noLive := fs.Bool("no-live", false, "don't tail CT logs on start (press w to toggle)")
	timeout := fs.Duration("timeout", 60*time.Second, "per-request timeout for search")
	interval := fs.Duration("interval", 15*time.Second, "poll interval per log")
	workers := fs.Int("workers", 4, "concurrent fetches per log")
	statePath := fs.String("state", "", "file to persist log offsets; resumes from it on restart")
	if err := fs.Parse(args); err != nil {
		return err
	}
	// The domain is optional here: without one the TUI opens on the domain prompt.
	var domain string
	switch fs.NArg() {
	case 0:
	case 1:
		d, err := ct.NormalizeDomain(fs.Arg(0))
		if err != nil {
			return err
		}
		domain = d
	default:
		fs.Usage()
		return errors.New("expected at most one domain")
	}
	if _, err := newSearcher(*source, *timeout, nil); err != nil {
		return err // reject a bad -source before taking over the terminal
	}

	model := tui.New(ctx, tui.Options{
		Domain:     domain,
		Subdomains: !*exact,
		Source:     *source,
		Watch:      !*noLive,
		Backend: tui.Backend{
			Search: func(ctx context.Context, domain, source string, warn io.Writer) ([]ct.Certificate, error) {
				s, err := newSearcher(source, *timeout, warn)
				if err != nil {
					return nil, err
				}
				return s.Search(ctx, domain, !*exact, *expired)
			},
			Watch: func(ctx context.Context, domain string, h tui.WatchHooks) error {
				w, err := newWatcher(ctx, watchConfig{
					domain: domain, subdomains: !*exact, interval: *interval, workers: *workers,
					statePath: *statePath, warn: h.Warn,
				})
				if err != nil {
					return err
				}
				w.Emit, w.Progress, w.Error = h.Emit, h.Progress, h.Error
				return w.Run(ctx)
			},
		},
	})
	_, err := tea.NewProgram(model, tea.WithContext(ctx)).Run()
	// SIGTERM cancels ctx and Bubble Tea reports that as "killed". It wraps panics in
	// ErrProgramKilled too, so only a cancelled context counts as a clean exit.
	if errors.Is(err, tea.ErrProgramKilled) && !errors.Is(err, tea.ErrProgramPanic) && ctx.Err() != nil {
		return nil
	}
	return err
}
