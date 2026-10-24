# patchcheck

Read-only checker for the October 2026 **PHP2Shell** (CVE-2026-109618 / CVE-2026-109619), **Node.js**
(Oct 21 release) and **Go** (CVE-2026-111943) advisories. It tells you whether the PHP, Node.js and Go
on a machine are at a patched version, and on Linux whether a running service still holds old code.

- No install, no dependencies beyond bash (3.2+) or PowerShell (5.1+) and standard Unix tools.
- Never changes the system and makes no network calls.
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

## What it checks

| | PHP | Node.js | Go |
|---|---|---|---|
| Binaries | `php`, `php-cgi`, `php-fpm` on `PATH` and common install dirs | `node`, `nodejs` | `go` |
| Running processes (Linux) | php-fpm, php-cgi, apache2/httpd, node whose binary was replaced after start | | |
| Containers | `--docker` | `--docker` | `--docker` |

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
- A web server may use a different PHP than the CLI. The script also looks for `php-fpm` and `php-cgi`,
  but Apache `mod_php` and IIS/FastCGI paths are not inspected: check them by hand.
- Windows: stale processes are not detected; restart IIS app pools, services and Node processes after upgrading.
- Go binaries embed the toolchain they were built with; upgrading Go does not fix a built binary, rebuild it.
- Version managers (nvm, asdf, pyenv-style shims) are only seen if their shim is on `PATH`.
- Patching does not remove an existing compromise. Review logs from 17 Oct 2026 onward.
- The Go advisory has the weakest sourcing. Advisory data comes from public vendor and press reports;
  confirm against the official PHP, Node.js and Go advisories.

## Development

```bash
make check        # shellcheck + bash tests + PowerShell tests (if pwsh is installed)
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for adding an advisory, [SECURITY.md](SECURITY.md) to report a wrong rule,
and [CHANGELOG.md](CHANGELOG.md). Licensed under the [MIT License](LICENSE).
