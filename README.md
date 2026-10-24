# patchcheck

Read-only checker for the October 2026 **PHP2Shell** (CVE-2026-109618 / CVE-2026-109619), **Node.js**
(Oct 21 release) and **Go** (CVE-2026-111943) advisories. It tells you whether the PHP, Node.js and Go
on a machine are at a patched version, and on Linux whether a running service still holds old code.

- No install, no dependencies beyond bash (3.2+) or PowerShell (5.1+) and standard Unix tools.
- The checker never changes the system and makes no network calls. (The separate daily monitor, below, only reads public feeds.)
- Rules live in one file, [`advisories.tsv`](advisories.tsv), shared by both scripts.

This project is **not** a patch. The fixes come from the PHP, Node.js and Go projects.

## Get it

```bash
git clone https://github.com/rahuldeeptech-spe/rd.git patchcheck && cd patchcheck
less patchcheck.sh            # read it first
./patchcheck.sh
```

Windows (PowerShell):

```powershell
powershell -ExecutionPolicy Bypass -File .\patchcheck.ps1
```

Tagged releases ship a tarball plus `SHA256SUMS` (`sha256sum -c SHA256SUMS`).
The scripts need `advisories.tsv` next to them, so download the whole tarball or clone the repo.

## Usage

| Option (bash / PowerShell) | Effect |
|---|---|
| `--docker` | also check running Docker containers (bash only) |
| `--json` / `-Json` | machine-readable output |
| `-q`, `--quiet` / `-Quiet` | only print problems |
| `--no-processes` | skip the stale-process check (bash only; Linux `/proc`) |
| `--managers` | also check runtimes from nvm, fnm, volta, asdf, phpbrew and `~/sdk/go*` (bash only) |
| `--go-binaries DIR` | scan Go binaries under `DIR` for the toolchain they were built with; needs `go` (bash only) |
| `--data FILE` / `-DataPath FILE` | use another advisories file |

| Exit code | Meaning |
|---|---|
| 0 | everything found is patched |
| 1 | vulnerable, or a running process still has the old binary |
| 2 | nothing known-vulnerable, but a version could not be confirmed |
| 64 | usage error |

Example output:

```
patchcheck 1.0.0 (advisory data: 2026-10-24)
[VULNERABLE]  host php 8.3.6 - update to >= 8.3.36 [CVE-2026-109618,CVE-2026-109619]
[OK]          host node 24.22.1 - >= 24.22.1 [NODEJS-2026-10-21]
[CHECK]       host go 1.25.13 - fix not confirmed. ... [CVE-2026-111943]
```

Use `--json` and the exit code for monitoring or CI gates.

## Daily security report

A scheduled GitHub Action (05:17 UTC) reads public feeds and publishes a report for the last 24 hours to the
[`reports` branch](https://github.com/rahuldeeptech-spe/rd/tree/reports):

| Feed | Used for |
|---|---|
| [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | bugs attackers are using right now |
| [NVD](https://nvd.nist.gov/) | new CVEs scored CRITICAL (9.0+), and any CVE that matches the watchlist |
| [GitHub Advisory Database](https://github.com/advisories) | reviewed critical advisories, plus high ones in watched ecosystems |
| nodejs.org, go.dev, php.net | newest releases, compared against `advisories.tsv` |

- **Alerts** are raised when a CVE is *about* a watched product itself (watchlist in [`monitor/watchlist.tsv`](monitor/watchlist.tsv): PHP, Node.js, Go,
  Python, OpenSSL, nginx, Apache), not merely mentioning it: a WordPress plugin that says "PHP" or a library that says "supports Python 3.6+"
  is counted in the report note but does not alert. Alerts are also raised when upstream ships a version that `advisories.tsv` does not know
  (or a version older than the file claims). An alert opens an `[alert]` issue.
- **Follow it:** Watch this repository (Custom > Issues) for alerts, or subscribe to
  `https://github.com/rahuldeeptech-spe/rd/commits/reports.atom`. The latest report is also machine-readable as
  [`latest.json`](https://github.com/rahuldeeptech-spe/rd/blob/reports/latest.json).
- **It never edits `advisories.tsv`.** A person confirms each change against the official advisory.
- **A failed feed is never shown as "all clear".** The report gets an `INCOMPLETE` banner, the section says the source was unavailable,
  and the workflow run fails so the repository owner is notified.

Limits: the report relays what the feeds say. NVD scores new CVEs with a delay, so a fresh CVE can show as unscored; CISA dates are
whole days, so an entry can appear in two consecutive reports. GitHub can pause scheduled workflows after 60 days without repository
activity; the daily commit normally counts, but check the Actions tab if reports stop.

Run it yourself: `python3 monitor/monitor.py --out out` (Python 3.9+, standard library only; `--sources node` runs a single feed).

## What it checks

| | PHP | Node.js | Go |
|---|---|---|---|
| Binaries | `php`, `php-cgi`, `php-fpm` on `PATH` and common install dirs | `node`, `nodejs` | `go` |
| Running processes (Linux) | php-fpm, php-cgi, apache2/httpd, node whose binary was replaced after start | | |
| Containers | `--docker` | `--docker` | `--docker` |
| Version managers | `--managers` | `--managers` | `--managers` |
| Built binaries | | | `--go-binaries DIR` |
| Apache `mod_php` | flagged `[CHECK]` when loaded (its version cannot be read from outside) | | |

Patched versions at the time of writing (see `advisories.tsv` for sources):

| Runtime | Patched |
|---|---|
| PHP | 8.5.12, 8.4.27, 8.3.36, 8.2.35 (8.1 and older: source backports only) |
| Node.js | 26.12.1, 24.22.1, 22.23.4 (18, 20, 21, 23, 25 are end-of-life) |
| Go | 1.26.10, 1.27.3 (1.25 and older: not confirmed) |

## Limits

- **Distro packages** (Debian, Ubuntu, RHEL) often backport a fix without changing the version number,
  so a patched system can show as `VULNERABLE`. Check the distro changelog, for example
  `apt changelog php8.3 | grep CVE-2026-109618`.
- A web server may use a different PHP than the CLI. The script also looks for `php-fpm` and `php-cgi`
  and flags a loaded Apache `mod_php`, but cannot read its version. IIS/FastCGI paths are not inspected: check them by hand.
- Windows: stale processes are not detected; restart IIS app pools, services and Node processes after upgrading.
- Go binaries embed the toolchain they were built with; upgrading Go does not fix a built binary, rebuild it.
- Version managers are only checked with `--managers`, and only in their default locations.
- Patching does not remove an existing compromise. Review logs from 17 Oct 2026 onward.
- The Go advisory has the weakest sourcing. Advisory data comes from public vendor and press reports;
  confirm against the official PHP, Node.js and Go advisories.

## Development

```bash
make check        # shellcheck + bash tests + PowerShell tests (if pwsh is installed)
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for adding an advisory, [SECURITY.md](SECURITY.md) to report a wrong rule,
and [CHANGELOG.md](CHANGELOG.md). Licensed under the [MIT License](LICENSE).
