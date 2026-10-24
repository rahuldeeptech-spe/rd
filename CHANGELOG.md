# Changelog

## 1.4.0 - 2026-10-24
- Homebrew formula `Formula/patchcheck.rb` (tap this repository). CI checks its syntax.
- `monitor/phpini.py`: read-only audit of risky PHP settings, from `php -r ini_get_all` or `--ini FILE`. Failure to run php is exit 3, never clean. 8 tests; two weak tests found by mutation and fixed.
- `monitor/exposed.py`: check your own site for publicly readable `.env`, `.git`, `phpinfo`, config backups and similar. Content-signature based, never prints content, 6 tests against a local server.

## 1.3.0 - 2026-10-24
- **.NET**: patchcheck lists every shared runtime from `dotnet --list-runtimes` (NETCore.App and AspNetCore.App) and judges them against the October 13 2026 servicing release (10.0.13, 9.0.21, 8.0.32; 7 and 6 out of support). Source: the official `dotnet/core` release metadata. Preview builds are reported as `[CHECK]`.
- `monitor/lockscan.py`: scan `package-lock.json` (v1-v3), `composer.lock`, `go.mod` and pinned `requirements.txt` against OSV.dev. Skipped non-exact versions are listed, a failed lookup exits 3, never clean. 13 tests; a CI job runs it against the real API on a known-vulnerable fixture (informational).
- `Dockerfile` and a container image published to GHCR with each release (attested). CI builds it and checks it runs as non-root.
- Chat alerts (`monitor/notify.py`): Telegram, Discord and Slack, once a day when the alert issue is opened. Feed text is sanitised, secrets never printed, one failing channel does not stop the others.
- Web page and Atom feed (`monitor/pages.py`) published on the `reports` branch for GitHub Pages. All feed text is escaped, only https links are used.
- GitHub Action (`action.yml`): `uses: rahuldeeptech-spe/rd@<tag>` runs patchcheck on the runner; `fail-on` and `args` inputs, `exit-code` output, job summary. Tested in CI on Linux and macOS.

## 1.2.0 - 2026-10-24
- **Node2Shell (CVE-2026-111497)**: the Node.js rules now carry the CVE id and the Node2Shell name and cite the official nodejs.org advisory. New checks for the Python packages `brotli` (< 1.2.1) and `brotlicffi` (< 1.2.1.0), from the GitHub reviewed advisory GHSA-9v8h-qqgm-4m35: the Python on `PATH`, each `--python PATH` (repeatable; virtualenvs), and containers with `--docker`. Python is run from `/` with `-E`, so a hostile directory or `PYTHONPATH` cannot get code executed (tested against the real interpreter). Bun is reported affected by security press but is not judged, because no primary source could be reached.
- The daily monitor now watches Brotli and Bun. `CVE-2026-111497` itself did not alert before: its description is about Google Brotli, not Node.js.
- Fixed in `patchcheck.ps1`: the same `php` or `node` reachable through a symlinked directory (`/bin` -> `/usr/bin`) was reported twice. The bash version was not affected.
- Version strings may have four parts (`brotlicffi` 1.2.1.0).

## 1.1.0 - 2026-10-24
- `install.sh`: download a release, verify its SHA-256, verify the build attestation when `gh` is available, refuse archives with absolute paths, `..` paths or links, check the version inside, then run `patchcheck` (or `--install-dir`). 82 tests, including tampered tarballs, hostile archives and every attestation mode.
- Releases are now attested (`actions/attest`) and the workflow verifies the attestation before publishing. Assets: the tarball, `SHA256SUMS` and `install.sh`.
- Weekly advisory data review: `monitor/propose.py` + `monitor/open_review.sh` + `data-review.yml` open a draft pull request that advances `#@ reviewed` lines (or an issue for Node.js security releases and new branches). The daily REVIEW alert now compares against the reviewed version, so a routine release no longer re-alerts every day once a person has read it.
- README: CI and daily-report badges and a link to today's report.
- Monitor: watchlist now also covers Java (Oracle Java SE, OpenJDK, GraalVM), Docker (Docker, Moby, containerd, runc), Kubernetes and WordPress core, with a per-product `deny` pattern. These products alert on new CVEs only; `patchcheck` does not check installed versions of them.

## 1.0.0 - 2026-10-24
First release.
- Rules moved to `advisories.tsv`, shared by `patchcheck.sh` and `patchcheck.ps1`.
- Checks PHP (CLI, php-cgi, php-fpm), Node.js and Go; `--docker` for running containers.
- Linux: detects running php-fpm / php-cgi / apache / node whose binary was replaced on disk (restart needed).
- `--json`, `--quiet`, `--no-processes`, `--data`; stable exit codes (0, 1, 2, 64).
- Test suites for bash and PowerShell; CI on Linux, macOS and Windows.
- Monitor: alerts only for CVEs that are *about* a watched product (the product is the subject of the description); apps and libraries that merely mention it are counted, not listed. Checked against 321 real NVD descriptions: exactly the 2 PHP2Shell CVEs and the 9 Node.js CVEs of the Oct 21 release alert.
- Daily security report: a scheduled workflow reads CISA KEV, NVD, the GitHub Advisory Database and the
  nodejs.org / go.dev / php.net release feeds, publishes a report to the `reports` branch and opens an
  `[alert]` issue for watchlist matches or stale/inconsistent rules. A failed feed marks the report INCOMPLETE.
- `patchcheck.sh`: `--managers` (nvm, fnm, volta, asdf, phpbrew, ~/sdk/go*), `--go-binaries DIR`, and a
  manual-check flag when Apache `mod_php` is loaded.
