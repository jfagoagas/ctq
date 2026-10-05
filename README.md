# ctq

An interactive [Certificate Transparency](https://certificate.transparency.dev/) explorer for the terminal.

![The Names tab: every name found for example.com, with certificate count, first certificate, expiry and issuers](docs/screenshots/names.png)

Point `ctq` at a domain and it shows every TLS certificate issued for it and its subdomains. Past certificates come from CT aggregators; new ones stream in straight from the CT logs within seconds of being logged. Typical uses are subdomain discovery, spotting certificates you didn't request, and keeping an inventory of what's exposed.

The same engine is available as plain CLI commands for scripts and pipes.

## Install

Download a binary for Linux, macOS or Windows (amd64 and arm64) from the [releases page](https://github.com/jfagoagas/ctq/releases), or install with Go 1.21 or later:

```sh
go install github.com/jfagoagas/ctq@latest
```

ctq needs Go 1.26 to build. Older Go versions (1.21+) download that toolchain automatically and print a "switching" message.

### Verify a release

Every archive in a release has a signed [SLSA build provenance](https://slsa.dev/) attestation and an SPDX SBOM attestation, both created by the release workflow. To check that a download was built from this repository by that workflow:

```sh
gh attestation verify ctq_<version>_linux_amd64.tar.gz --repo jfagoagas/ctq
```

Add `--predicate-type https://spdx.dev/Document/v2.3` to verify the SBOM attestation instead. The SBOM itself is attached to the release next to each archive (`*.sbom.json`), so you can scan a release for known vulnerabilities without running it:

```sh
grype sbom:ctq_<version>_linux_amd64.tar.gz.sbom.json
```

Releases are gated on the same scan: nothing is published while a fixable high or critical vulnerability is known in the Go toolchain or a dependency. The latest release's SBOMs are rescanned every week.

Or from source:

```sh
git clone https://github.com/jfagoagas/ctq
cd ctq
go build .
```

## The TUI

```sh
ctq tui example.com
ctq tui            # opens on the domain prompt
```

The search and the live feed start together. Press `d` at any time to switch to another domain.

<table>
  <tr>
    <td width="50%"><img src="docs/screenshots/searching.png" alt="First launch: the search runs while the live feed connects to 64 CT logs"></td>
    <td width="50%"><img src="docs/screenshots/history.png" alt="The History tab: one row per certificate, with validity, issuer and source"></td>
  </tr>
  <tr>
    <td>On launch, the search runs while the live feed connects to every CT log.</td>
    <td>History lists one row per certificate. The header shows which source answered: here crt.sh failed and <code>auto</code> fell back to Cert Spotter.</td>
  </tr>
  <tr>
    <td width="50%"><img src="docs/screenshots/live.png" alt="The Live tab while watching 64 CT logs"></td>
    <td width="50%"><img src="docs/screenshots/names.png" alt="The Names tab sorted by zone"></td>
  </tr>
  <tr>
    <td>Live shows certificates as they're logged. Until one arrives, it says how many logs it's watching.</td>
    <td>Names merges History and Live into one row per name, sorted by zone so a subdomain's children stay together.</td>
  </tr>
</table>

| Tab | Content |
|-----|---------|
| History | certificates already logged, from crt.sh or Cert Spotter |
| Live | certificates arriving from the CT logs, newest first |
| Names | every unique name from both, with status, certificate count, first certificate, latest expiry and issuers |
| Logs | health of each CT log the live feed reads: position, lag, status and last error |

Names sorts by zone by default (`api.dev.example.com` next to `web.dev.example.com`). Press `o` to sort by newest first certificate, soonest expiry, or most certificates. The status column tags each name:

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

`ctq tui` accepts the `search` flags `-source`, `-exact`, `-expired` and `-timeout`, the `watch` flags `-interval`, `-workers` and `-state`, and `-no-live` to start with the live feed off.

## CLI

The TUI is built on two commands you can also run on their own:

```
ctq search [flags] <domain>   certificates already logged (crt.sh, Cert Spotter)
ctq watch  [flags] <domain>   new certificates, tailed directly from all CT logs
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

## Related projects

`ctq` is for exploring a domain interactively. For other jobs, these tools are a better fit:

- [certspotter](https://github.com/SSLMate/certspotter): unattended monitoring of a watchlist, with alerts through scripts or email. Made by SSLMate, who also run the Cert Spotter API that `ctq search` uses.
- [gungnir](https://github.com/g0ldencybersec/gungnir): streams new domains from all CT logs to stdout, JSONL or NATS, for recon pipelines.
- [subfinder](https://github.com/projectdiscovery/subfinder): passive subdomain enumeration from many sources, crt.sh among them.
- [ctfr](https://github.com/UnaPibaGeek/ctfr) and [crt](https://github.com/cemulus/crt): quick crt.sh subdomain lookups from the command line.

## Development

```sh
go test -race ./...
CTQ_LIVE=1 go test -run TestLive -v ./internal/ct/   # checks parsing against real CT logs
```

Unit tests use local HTTP servers and fakes; nothing touches the network unless `CTQ_LIVE` is set.

CI also validates the release config, audits the workflows with [zizmor](https://docs.zizmor.sh/), and scans each platform's binary with [syft](https://github.com/anchore/syft) and [grype](https://github.com/anchore/grype). To run the same checks locally:

```sh
goreleaser check
zizmor --persona auditor .github/
grype dir:.   # dependencies only; CI scans the built binary, which adds the Go stdlib
```

To accept a grype finding that doesn't apply to ctq, add it to `.grype.yaml` with a reason.

Releases are cut by pushing a `v*` tag; `.github/workflows/release.yml` does the rest.

## License

[MIT](LICENSE)
