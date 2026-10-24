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
Add a line to `monitor/watchlist.tsv`: `name<TAB>keywords<TAB>ecosystems<TAB>extra<TAB>deny` (use `-` for an empty column; `extra` and `deny` are optional).
- `keywords` match whole words, case-insensitive (avoid short or common words such as `go`); a hit means the CVE *mentions* the product.
- A CVE is *about* the product when the product is the subject of its description: the words before it are only things like
  "A flaw in", "In", "A heap overflow in the" (see `_LEAD_OK` in `monitor/monitor.py`). Only "about" CVEs raise alerts.
- `extra` is an optional Python regex for phrasings the subject rule cannot see. Keep it tight: an extra pattern that matches in the middle of a
  sentence will also match apps ("routes .phar to PHP-FPM", "on PHP before 8.0"), which is how the first version of this filter produced false alerts.
- Add real descriptions of both kinds to `Classification` in `monitor/test_monitor.py`, including the ones that must not alert.
- `deny` is an optional Python regex that vetoes a match for phrasings that look like the product but are not ("A Docker image of ..."). Anchor it with `^` when you only mean the start of the description.
- `ecosystems` (`npm`, `pip`, `composer`, `go`, `maven`, ...) decide which high-severity GitHub advisories are listed; critical ones are always listed.

## Handling the weekly data-review pull request
It is a draft. For each row in its table: open the notes (the link is in the row), look for security fixes.
- No security fix: merge the pull request. That only moves the `#@ reviewed` lines and silences the daily REVIEW alert up to that version.
- A security fix: do not merge as is. Add rows to `advisories.tsv` (new advisory id, the fixed version, an https source) and remove that line from the diff.
  A Node.js security release is never in the diff; it is in the issue.

## Before opening a PR
```bash
make check                       # shellcheck + bash tests + monitor tests (+ PowerShell tests if pwsh is installed)
```
Add a test case for any behaviour change in both `tests/run.sh` and `tests/run.ps1`.

## Rules for the scripts
- Read-only, no network, no `sudo`, no `eval`.
- Never print or execute anything taken from the advisories file.
- bash 3.2 compatible (macOS); PowerShell 5.1 compatible.
