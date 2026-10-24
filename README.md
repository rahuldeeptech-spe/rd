# patchcheck

[![CI](https://github.com/rahuldeeptech-spe/rd/actions/workflows/ci.yml/badge.svg)](https://github.com/rahuldeeptech-spe/rd/actions/workflows/ci.yml)
[![Daily security report](https://github.com/rahuldeeptech-spe/rd/actions/workflows/daily-report.yml/badge.svg)](https://github.com/rahuldeeptech-spe/rd/actions/workflows/daily-report.yml)

**[Today's security report](https://github.com/rahuldeeptech-spe/rd/blob/reports/README.md)** (refreshed daily at 05:17 UTC) · [Latest release](https://github.com/rahuldeeptech-spe/rd/releases/latest) · [Open alerts](https://github.com/rahuldeeptech-spe/rd/issues?q=is%3Aissue+is%3Aopen+%5Balert%5D)

Read-only checker for the October 2026 **PHP2Shell** (CVE-2026-109618 / CVE-2026-109619), **Node2Shell**
(CVE-2026-111497, in the Node.js Oct 21 release and in the Python `brotli` packages) and **Go** (CVE-2026-111943)
advisories. It tells you whether the PHP, Node.js, Go and Python Brotli packages on a machine are at a patched version,
and on Linux whether a running service still holds old code.

- No install, no dependencies beyond bash (3.2+) or PowerShell (5.1+) and standard Unix tools.
- The checker never changes the system and makes no network calls. (The separate daily monitor, below, only reads public feeds.)
- Rules live in one file, [`advisories.tsv`](advisories.tsv), shared by both scripts.

This project is **not** a patch. The fixes come from the PHP, Node.js and Go projects.

## Get it

**Recommended (Linux/macOS): the installer.** It downloads a release, verifies it, runs `patchcheck` and cleans up:

```bash
curl -fsSLO https://github.com/rahuldeeptech-spe/rd/releases/latest/download/install.sh
less install.sh                      # read it first
bash install.sh                      # latest release: download, verify, run
bash install.sh -- --docker --json   # everything after -- goes to patchcheck
bash install.sh --version v1.1.0     # a specific release
bash install.sh --install-dir ~/tools   # keep it instead of running it
```

Before anything from the download is executed, `install.sh` checks (1) the tarball's SHA-256 against the release's `SHA256SUMS`,
(2) if the [GitHub CLI](https://cli.github.com/) is installed and logged in (`gh auth login`), the **build provenance attestation**, which proves
the tarball was produced by this repository's release workflow, (3) that the archive has no absolute paths, `..` paths or links, and (4) that
the version inside matches the tag. **Without `gh` only the checksum protects you, and it comes from the same place as the file**, so
it catches corruption but not a replaced release. `--require-attestation` makes a missing `gh` an error; `--no-attestation` skips step 2.

**Verify a release by hand** (any OS):

```bash
gh attestation verify patchcheck-v1.1.0.tar.gz --repo rahuldeeptech-spe/rd
sha256sum -c SHA256SUMS
```

Windows (PowerShell): download `patchcheck-v1.1.0.tar.gz` and `SHA256SUMS` from the [release](https://github.com/rahuldeeptech-spe/rd/releases/latest), then

```powershell
(Get-FileHash .\patchcheck-v1.1.0.tar.gz -Algorithm SHA256).Hash.ToLower()   # must equal the line for the tarball in SHA256SUMS
tar -xzf .\patchcheck-v1.1.0.tar.gz -C patchcheck
powershell -ExecutionPolicy Bypass -File .\patchcheck\patchcheck.ps1
```

There is no PowerShell installer yet. Or clone the repository:

```bash
git clone https://github.com/rahuldeeptech-spe/rd.git patchcheck && cd patchcheck
./patchcheck.sh
```

The scripts need `advisories.tsv` next to them, so use the whole tarball or clone the repo.

## Usage

| Option (bash / PowerShell) | Effect |
|---|---|
| `--docker` | also check running Docker containers (bash only) |
| `--json` / `-Json` | machine-readable output |
| `-q`, `--quiet` / `-Quiet` | only print problems |
| `--no-processes` | skip the stale-process check (bash only; Linux `/proc`) |
| `--managers` | also check runtimes from nvm, fnm, volta, asdf, phpbrew and `~/sdk/go*` (bash only) |
| `--go-binaries DIR` | scan Go binaries under `DIR` for the toolchain they were built with; needs `go` (bash only) |
| `--python PATH` / `-Python PATH` | also check the Brotli packages of this Python, for example a virtualenv's `bin/python` (repeatable) |
| `--data FILE` / `-DataPath FILE` | use another advisories file |

| Exit code | Meaning |
|---|---|
| 0 | everything found is patched |
| 1 | vulnerable, or a running process still has the old binary |
| 2 | nothing known-vulnerable, but a version could not be confirmed |
| 64 | usage error |

Example output:

```
patchcheck 1.1.0 (advisory data: 2026-10-24)
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
| [NVD](https://nvd.nist.gov/) | new CVEs scored CRITICAL (9.0+), and CVEs about a watched product |
| [GitHub Advisory Database](https://github.com/advisories) | reviewed critical advisories, plus high ones in watched ecosystems |
| nodejs.org, go.dev, php.net | newest releases, compared against `advisories.tsv` |

- **Alerts** are raised when a CVE is *about* a watched product (watchlist in [`monitor/watchlist.tsv`](monitor/watchlist.tsv): PHP, Node.js, Go,
  Python, OpenSSL, nginx, Apache, Java, Docker, Kubernetes, WordPress core), meaning the product is the subject of the description ("PHP uses longjmp()...", "A flaw in Node.js TLS..."). An app that
  merely mentions it ("PhpSpreadsheet is a PHP library", "follow-redirects is a Node.js client", "Traefik ... Ingress NGINX provider") is counted in the
  report note but does not alert. Alerts are also raised when upstream ships a version that `advisories.tsv` does not know (or one older than the
  file claims). An alert opens an `[alert]` issue.
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

## Weekly data review

`advisories.tsv` is only as good as the person who last read the release notes. Every Monday (06:43 UTC) the
[`data-review`](.github/workflows/data-review.yml) workflow compares the newest PHP, Node.js and Go releases with what the file has been reviewed up to:

- **A draft pull request** advances the `#@ reviewed` lines for releases that look routine. **Merging it is your statement that you read the notes.**
  It never changes a fixed version and never invents an advisory.
- **An issue** lists what needs a person: a Node.js release that nodejs.org flags as a *security* release (it is never marked reviewed by the bot;
  the daily report keeps raising a REVIEW alert until someone adds the rows), and new upstream branches with no rule.
- If GitHub refuses to let Actions open pull requests (Settings > Actions > General > "Allow GitHub Actions to create and approve pull requests"),
  the workflow opens an issue with a ready-made compare link instead.

php.net and go.dev publish no security flag, so for those the pull request says so and links the release notes.

## Node2Shell (CVE-2026-111497)

The name comes from security press (one outlet credits Imperva); the Node.js advisory does not use it. The bug is an out-of-bounds write in the
Brotli decoder. [Node.js' advisory](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases) rates it High and says an attacker who can
supply Brotli data that an application decompresses with `node:zlib` can corrupt process memory, which can lead to a crash, disclosure of process
memory or remote code execution. The [GitHub reviewed advisory](https://github.com/advisories/GHSA-9v8h-qqgm-4m35) scores it 9.2 (CVSS v4, Critical).

| What | Affected | Fixed |
|---|---|---|
| Node.js | 22.x, 24.x, 26.x | 22.23.4, 24.22.1, 26.12.1. End-of-life lines are always affected and get no fix |
| Python `brotli` | 1.0.3 to 1.2.0 | 1.2.1 |
| Python `brotlicffi` | 1.0.3 to 1.2.0.x | 1.2.1.0 |
| Google Brotli library | 1.0.3 to 1.2.0 | 1.0.10, 1.1.1, 1.2.1 |

- Node.js lists **no workaround**: upgrade the runtime. The Brotli decoder is compiled into the Node.js binary, so updating an npm package does not help.
- Rejecting `Content-Encoding: br` requests at a proxy is mentioned by security press as reducing inbound exposure only; it does nothing for Brotli
  responses your own code fetches. Treat that as unverified.
- A third-party write-up says Debian builds Node.js against the system `libbrotli`, so a Debian fix would arrive through the `brotli` package, not through the Node.js
  version number. Unverified: check your distribution's security tracker before trusting a `VULNERABLE` or `OK` for a distro `node`.
- Check your servers: `bash install.sh -- --python /path/to/venv/bin/python` (or `--docker`).

## What it checks

| | PHP | Node.js | Go |
|---|---|---|---|
| Binaries | `php`, `php-cgi`, `php-fpm` on `PATH` and common install dirs | `node`, `nodejs` | `go` |
| Running processes (Linux) | php-fpm, php-cgi, apache2/httpd, node whose binary was replaced after start | | |
| Containers | `--docker` | `--docker` | `--docker` |
| Version managers | `--managers` | `--managers` | `--managers` |
| Python packages `brotli`, `brotlicffi` (Node2Shell) | `python3` / `python` on `PATH`, plus each `--python`, plus containers with `--docker` | | |
| Built binaries | | | `--go-binaries DIR` |
| Apache `mod_php` | flagged `[CHECK]` when loaded (its version cannot be read from outside) | | |

Patched versions at the time of writing (see `advisories.tsv` for sources):

| Runtime | Patched |
|---|---|
| PHP | 8.5.12, 8.4.27, 8.3.36, 8.2.35 (8.1 and older: source backports only) |
| Node.js | 26.12.1, 24.22.1, 22.23.4 (18, 20, 21, 23, 25 are end-of-life) |
| Go | 1.26.10, 1.27.3 (1.25 and older: not confirmed) |
| Python `brotli` / `brotlicffi` | 1.2.1 / 1.2.1.0 (Node2Shell; every older release is affected from 1.0.3) |

## Limits

- **Distro packages** (Debian, Ubuntu, RHEL) often backport a fix without changing the version number,
  so a patched system can show as `VULNERABLE`. Check the distro changelog, for example
  `apt changelog php8.3 | grep CVE-2026-109618`.
- A web server may use a different PHP than the CLI. The script also looks for `php-fpm` and `php-cgi`
  and flags a loaded Apache `mod_php`, but cannot read its version. IIS/FastCGI paths are not inspected: check them by hand.
- Windows: stale processes are not detected; restart IIS app pools, services and Node processes after upgrading.
- Go binaries embed the toolchain they were built with; upgrading Go does not fix a built binary, rebuild it.
- Version managers are only checked with `--managers`, and only in their default locations.
- Python packages are read from the interpreter you point at. Most real installs live in virtualenvs and containers, so pass each one with
  `--python /path/to/venv/bin/python` (or use `--docker`). The check needs Python 3.8+ and is run from `/` with `-E`, so a hostile
  file in the current directory or in `PYTHONPATH` is never imported.
- Bun is also reported to be affected by Node2Shell (fixed in 1.4.4, per security press). I could not confirm that from Bun's own release
  notes, so `patchcheck` does not judge Bun versions; the daily report watches Bun and Brotli for new CVEs.
- Patching does not remove an existing compromise. Review logs from 17 Oct 2026 onward.
- The Go advisory has the weakest sourcing. Advisory data comes from public vendor and press reports;
  confirm against the official PHP, Node.js and Go advisories.

## Development

```bash
make check        # shellcheck + bash tests + PowerShell tests (if pwsh is installed)
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for adding an advisory, [SECURITY.md](SECURITY.md) to report a wrong rule,
and [CHANGELOG.md](CHANGELOG.md). Licensed under the [MIT License](LICENSE).
