# Changelog

## Unreleased
- Monitor: alerts only for CVEs about a watched product itself (per-product `core` pattern); apps and libraries that merely mention it are counted, not listed. First live run showed 22 mostly-irrelevant alerts without this.
- Daily security report: a scheduled workflow reads CISA KEV, NVD, the GitHub Advisory Database and the
  nodejs.org / go.dev / php.net release feeds, publishes a report to the `reports` branch and opens an
  `[alert]` issue for watchlist matches or stale/inconsistent rules. A failed feed marks the report INCOMPLETE.
- `patchcheck.sh`: `--managers` (nvm, fnm, volta, asdf, phpbrew, ~/sdk/go*), `--go-binaries DIR`, and a
  manual-check flag when Apache `mod_php` is loaded.

## 1.0.0 - 2026-10-24
- Rules moved to `advisories.tsv`, shared by `patchcheck.sh` and `patchcheck.ps1`.
- Checks PHP (CLI, php-cgi, php-fpm), Node.js and Go; `--docker` for running containers.
- Linux: detects running php-fpm / php-cgi / apache / node whose binary was replaced on disk (restart needed).
- `--json`, `--quiet`, `--no-processes`, `--data`; stable exit codes (0, 1, 2, 64).
- Test suites for bash and PowerShell; CI on Linux, macOS and Windows.
