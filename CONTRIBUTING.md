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

## Before opening a PR
```bash
make check                       # shellcheck + bash tests (+ PowerShell tests if pwsh is installed)
```
Add a test case for any behaviour change in both `tests/run.sh` and `tests/run.ps1`.

## Rules for the scripts
- Read-only, no network, no `sudo`, no `eval`.
- Never print or execute anything taken from the advisories file.
- bash 3.2 compatible (macOS); PowerShell 5.1 compatible.
