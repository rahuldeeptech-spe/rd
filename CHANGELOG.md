# Changelog

## Unreleased
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
