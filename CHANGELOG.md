# Changelog

## 1.0.0 - 2026-10-24
- Rules moved to `advisories.tsv`, shared by `patchcheck.sh` and `patchcheck.ps1`.
- Checks PHP (CLI, php-cgi, php-fpm), Node.js and Go; `--docker` for running containers.
- Linux: detects running php-fpm / php-cgi / apache / node whose binary was replaced on disk (restart needed).
- `--json`, `--quiet`, `--no-processes`, `--data`; stable exit codes (0, 1, 2, 64).
- Test suites for bash and PowerShell; CI on Linux, macOS and Windows.
