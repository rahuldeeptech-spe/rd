# Security policy

## What counts as a security issue here
- A wrong or missing rule in `advisories.tsv` that makes a vulnerable version report `OK` (false negative).
- Anything that makes the scripts modify the system, send data anywhere, or execute untrusted input.

The scripts are read-only and make no network calls. They only run `php -v`, `node -v`, `go version`
(and `docker exec ... -v` with `--docker`) on binaries already on the host.

## Reporting
Use GitHub's private "Report a vulnerability" button on the Security tab of this repository.
Please do not open a public issue for a false negative that affects a currently exploited bug.

## Trust the data, but verify it
Advisory data is compiled from public vendor and security-press sources and may contain errors.
Always confirm against the official PHP, Node.js and Go advisories before declaring a system safe.
