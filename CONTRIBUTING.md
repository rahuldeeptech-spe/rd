# Contributing

## Adding or changing an advisory
Edit `advisories.tsv` only; both scripts read it. One rule per line, tab-separated:

```
runtime  branch  status  fixed  id  source  note
```

- `status`: `fixed` (needs a `fixed` version), `eol` (no upstream fix), `unconfirmed` (needs a manual look).
- Every runtime keeps an `older` and a `newer` fallback row.
- `source` must be an https link to the vendor advisory or release notes. Prefer two independent sources;
  if you only have one, say so in `note` and use `unconfirmed` until it is confirmed.
- Bump `#@ updated YYYY-MM-DD` and add a line to `CHANGELOG.md`.

## Watching more products
Add a line to `monitor/watchlist.tsv`: `name<TAB>keywords<TAB>ecosystems<TAB>core`.
- `keywords` match whole words, case-insensitive (avoid short or common words such as `go`); a hit means the CVE *mentions* the product.
- `core` is an optional Python regex (case-insensitive) that decides whether the CVE is *about* the product itself. Only core hits raise alerts.
  Without it, every mention alerts, which is noisy for words like `php` or `python` that appear in thousands of third-party apps.
  Add real descriptions of both kinds to `Classification` in `monitor/test_monitor.py`.
- `ecosystems` (`npm`, `pip`, `composer`, `go`, `maven`, ...) decide which high-severity GitHub advisories are listed; critical ones are always listed.

## Before opening a PR
```bash
make check                       # shellcheck + bash tests + monitor tests (+ PowerShell tests if pwsh is installed)
```
Add a test case for any behaviour change in both `tests/run.sh` and `tests/run.ps1`.

## Rules for the scripts
- Read-only, no network, no `sudo`, no `eval`.
- Never print or execute anything taken from the advisories file.
- bash 3.2 compatible (macOS); PowerShell 5.1 compatible.
