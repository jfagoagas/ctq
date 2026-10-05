# ctq

Query [Certificate Transparency](https://certificate.transparency.dev/) for a domain.

`ctq` finds the TLS certificates issued for a domain and its subdomains. It looks up past certificates through CT aggregators, and it can tail the CT logs themselves to report new certificates within seconds of issuance. Typical uses are subdomain discovery, spotting certificates you didn't request, and keeping an inventory of what's exposed.

It runs as a plain CLI for scripts and pipes, or as an interactive TUI.

## Install

Requires Go 1.26 or later.

```sh
go install github.com/jfagoagas/ctq@latest
```

Or from source:

```sh
git clone https://github.com/jfagoagas/ctq
cd ctq
go build .
```

## Usage

```
ctq search [flags] <domain>   certificates already logged (crt.sh, Cert Spotter)
ctq watch  [flags] <domain>   new certificates, tailed directly from all CT logs
ctq tui    [flags] [domain]   interactive: history, live feed and subdomain inventory
```

The domain covers its subdomains by default. Pass `-exact` to match only the domain itself. Wildcard input such as `*.example.com` is treated as `example.com`.

### search

```sh
ctq search example.com                  # unique names, one per line
ctq search -o table example.com         # one row per certificate
ctq search -o json example.com | jq .   # full records
ctq search -source crtsh -expired example.com
```

| Flag | Default | Description |
|------|---------|-------------|
| `-source` | `auto` | `auto`, `crtsh` or `certspotter` |
| `-o` | `names` | `names`, `table` or `json` |
| `-exact` | `false` | only the domain itself, no subdomains |
| `-expired` | `false` | include expired certificates (crt.sh only) |
| `-issuer` | | only certificates whose issuer contains this text |
| `-timeout` | `60s` | per-request timeout |

`auto` tries crt.sh first and falls back to Cert Spotter if crt.sh fails, which happens often under load.

### watch

```sh
ctq watch example.com
ctq watch -json example.com >> example.jsonl
ctq watch -state ~/.ctq-state.json -v example.com
```

Each match prints one line with the time, entry type (`cert` or `precert`), issuer, matching names and log. A certificate seen in several logs is reported once.

| Flag | Default | Description |
|------|---------|-------------|
| `-exact` | `false` | only the domain itself, no subdomains |
| `-interval` | `15s` | poll interval per log |
| `-workers` | `4` | concurrent fetches per log |
| `-state` | | file that stores log positions, so a restart resumes where it stopped |
| `-log` | | only logs whose name contains this text |
| `-json` | `false` | emit JSON lines |
| `-v` | `false` | print progress and lag per log to stderr |

Without `-state`, `watch` starts at the current end of each log and only reports certificates logged after it starts. If `-v` shows lag growing, raise `-workers`.

### tui

```sh
ctq tui example.com
ctq tui            # opens on the domain prompt
```

The TUI has four tabs:

| Tab | Content |
|-----|---------|
| History | certificates from `search` |
| Live | certificates arriving from the CT logs, newest first |
| Names | every unique name from both, with status, certificate count, first certificate, latest expiry and issuers |
| Logs | health of each CT log the live feed reads: position, lag, status and last error |

The Names tab sorts by zone by default, so a subdomain's children stay together (`api.dev.example.com` next to `web.dev.example.com`). Press `o` to sort by newest first certificate, soonest expiry, or most certificates. The status column tags each name:

| Tag | Meaning |
|-----|---------|
| `new` | first certificate in the last 7 days |
| `live` | seen in the live feed this session |
| `expiring` | latest certificate expires within 14 days |
| `expired` | every certificate for the name has expired |

A log that fails a poll shows as `retrying` and is retried on the next poll. After 3 failures in a row it shows as `failing`. Tiled logs sometimes publish a checkpoint before its tiles are readable, so an occasional `retrying` is normal.

| Key | Action |
|-----|--------|
| `d` | search a different domain |
| `tab`, `shift+tab`, `1`-`4` | switch tab |
| `↑` `↓` | move |
| `/` | filter by name, issuer or log (`esc` clears) |
| `enter` | show details for the selected row |
| `o` | change the sort order (Names tab) |
| `r` | search again |
| `s` | cycle the search source |
| `w` | turn the live feed on or off |
| `q` | quit |

It accepts the `search` flags `-source`, `-exact`, `-expired` and `-timeout`, the `watch` flags `-interval`, `-workers` and `-state`, and `-no-live` to start with the live feed off.

## How it works

Certificate Transparency logs are append-only Merkle trees. Chrome and Safari reject publicly trusted certificates that weren't logged, so CAs submit every certificate they issue. The logs can only be read by position: there is no way to ask a log for one domain's certificates. Searching by domain needs a service that has read every log and indexed the result.

So `ctq` uses two kinds of sources:

| Command | Source | What it covers |
|---------|--------|----------------|
| `search` | [crt.sh](https://crt.sh) | full history including expired certificates; one request, but its database times out on large domains |
| `search` | [Cert Spotter](https://sslmate.com/certspotter/) | unexpired certificates only; paginated and more reliable |
| `watch` | the CT logs in [Chrome's log list](https://www.gstatic.com/ct/log_list/v3/log_list.json) | new entries from the moment it starts |

`watch` reads both log protocols in use today: [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962) and the tiled [static-ct-api](https://c2sp.org/static-ct-api), which Let's Encrypt and others have moved to. It skips logs whose expiry window has already closed, since they receive no new certificates.

## Configuration

| Variable | Description |
|----------|-------------|
| `CERTSPOTTER_API_KEY` | Cert Spotter API key. Without one, the API allows about 10 requests per hour, and each page of results is one request. |

## Limitations

- `watch` doesn't verify log signatures or Merkle inclusion proofs. It trusts the log operators and TLS, which is fine for finding certificates but not for auditing logs.
- crt.sh is a free, shared service and is often overloaded. Expect timeouts on large domains; `auto` falls back to Cert Spotter.
- Cert Spotter doesn't return expired certificates, so `-expired` only works with crt.sh.
- Duplicate detection in `watch` keeps a bounded set of recent certificates, so a rare duplicate can get through on a long run.

## Development

```sh
go test -race ./...
CTQ_LIVE=1 go test -run TestLive -v ./internal/ct/   # checks parsing against real CT logs
```

Unit tests use local HTTP servers and fakes; nothing touches the network unless `CTQ_LIVE` is set.

## License

[MIT](LICENSE)
