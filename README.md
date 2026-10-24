# PHP2Shell / Node.js / Go Oct-2026 patch checker

Read-only script that tells you whether the PHP and Node.js on your machine
have the fixes for:

- **PHP2Shell**: CVE-2026-109618 and CVE-2026-109619 (unauthenticated RCE in PHP)
- **Node.js** Oct 21 2026 security release (includes CVE-2026-111497, Brotli decoder)
- **Go** CVE-2026-111943 (`crypto/x509` certificate trust). Lower confidence: sources
  disagree on details, and no fix for Go 1.25 or older is confirmed.

This repo does **not** contain a patch. The fixes come from the PHP and Node.js
projects; this script only checks whether you have them.

## Run

```bash
curl -O https://raw.githubusercontent.com/rahuldeeptech-spe/rd/main/check-php2shell.sh
less check-php2shell.sh        # read it first
bash check-php2shell.sh        # host
bash check-php2shell.sh --docker   # also running containers
```

Windows (PowerShell):

```powershell
powershell -ExecutionPolicy Bypass -File .\check-php2shell.ps1
```

The PowerShell version is **untested** (written without a Windows/pwsh environment).
Treat its output as a hint and compare with `php -v` / `node -v` / `go version`.

Exit code is `0` if everything is patched, `1` otherwise.

## Fixed versions

| Runtime | Patched |
|---|---|
| PHP | 8.5.12, 8.4.27, 8.3.36, 8.2.35 |
| PHP 8.1 and older | no new release, source-level backports only |
| Node.js | 26.12.1, 24.22.1, 22.23.4 |
| Node.js 18, 20, 21, 23, 25 | end-of-life, no fix |
| Go | 1.26.10, 1.27.3 (1.25 and older: not confirmed) |

## Limits

- Distro packages (Debian, Ubuntu, RHEL) often backport fixes without changing the
  version number. If the script flags a distro PHP, check the distro security tracker.
- Go binaries embed the toolchain they were built with: upgrading Go does not fix
  an already-built binary, rebuild it.
- Only the CLI and Docker containers are checked. A web server can run a different
  PHP than the CLI, so also run `php-fpm -v` or check your Apache/Nginx setup.
- After upgrading, restart php-fpm / Apache / your Node processes.
- Patching does not remove an existing compromise. Review logs from 17 Oct 2026 onward.

## Sources

Check the official PHP and Node.js advisories before acting.
