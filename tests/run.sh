#!/usr/bin/env bash
# Hermetic tests for patchcheck.sh: fake php/node/go binaries, fake /proc, restricted PATH.
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
PASS=0; FAIL=0

# Only the tools patchcheck.sh needs, so a real php/node/go on the host can never leak in.
TOOLS="$WORK/tools"; mkdir -p "$TOOLS"
for t in awk sed grep head tr wc cat readlink dirname basename sort uname cut; do
  p="$(command -v "$t")" && ln -s "$p" "$TOOLS/$t"
done

stub() { # stub DIR NAME OUTPUT  - a binary that prints OUTPUT whatever its arguments
  printf '#!/bin/sh\necho "%s"\n' "$3" > "$1/$2"; chmod +x "$1/$2"
}

run() { # run NAME EXPECTED_EXIT PATTERN [patchcheck args] ; uses $BIN as the stub dir
  local name="$1" want="$2" pat="$3" out rc; shift 3
  out="$(PATH="$BIN:$TOOLS" PATCHCHECK_SEARCH_DIRS="$BIN" PATCHCHECK_PROC_DIR="$WORK/noproc" \
        "$BASH" "$ROOT/patchcheck.sh" "$@" 2>&1)"; rc=$?
  if [ "$rc" = "$want" ] && printf '%s' "$out" | grep -Eq -- "$pat"; then
    PASS=$((PASS + 1)); echo "ok   $name"
  else
    FAIL=$((FAIL + 1)); echo "FAIL $name (exit $rc, wanted $want, pattern '$pat')"; printf '%s\n' "$out" | sed 's/^/     | /'
  fi
}

check() { # check NAME CMD... : pass when CMD succeeds
  local name="$1"; shift
  if "$@"; then PASS=$((PASS + 1)); echo "ok   $name"; else FAIL=$((FAIL + 1)); echo "FAIL $name"; fi
}

newbin() { BIN="$WORK/bin.$1"; rm -rf "$BIN"; mkdir -p "$BIN"; }

newbin patched;   stub "$BIN" php "PHP 8.3.36 (cli)"; stub "$BIN" node v24.22.1; stub "$BIN" go "go version go1.26.10 linux/amd64"
run "all patched"                 0 'everything found is patched'
run "all patched, json"           0 '"exit_code":0'                       --json

newbin phpold;    stub "$BIN" php "PHP 8.3.35 (cli)"; stub "$BIN" node v24.22.1; stub "$BIN" go "go version go1.27.3 linux/amd64"
run "php one patch behind"        1 'VULNERABLE.*php 8.3.35.*>= 8.3.36'
newbin phpfix;    stub "$BIN" php "PHP 8.5.12 (cli)"; stub "$BIN" node v26.12.1; stub "$BIN" go "go version go1.26.10 linux/amd64"
run "boundary: exactly fixed"     0 'OK.*php 8.5.12'
newbin php81;     stub "$BIN" php "PHP 8.1.30 (cli)"
run "php 8.1 (backport only)"     1 'VULNERABLE.*php 8.1.30.*no upstream fix'
newbin php74;     stub "$BIN" php "PHP 7.2.1 (cli)"
run "php far older -> older rule" 1 'VULNERABLE.*php 7.2.1.*Unsupported'
newbin phpnew;    stub "$BIN" php "PHP 8.6.0 (cli)"
run "php newer than data -> check" 2 'CHECK.*php 8.6.0'

newbin node20;    stub "$BIN" node v20.11.0
run "node 20 is EOL"              1 'VULNERABLE.*node 20.11.0'
newbin node25;    stub "$BIN" node v25.1.0
run "node 25 (odd, EOL)"          1 'VULNERABLE.*node 25.1.0'
newbin node22old; stub "$BIN" node v22.23.3
run "node 22 one patch behind"    1 'node 22.23.3.*>= 22.23.4'

newbin go125;     stub "$BIN" go "go version go1.25.13 linux/amd64"
run "go 1.25 unconfirmed"         2 'CHECK.*go 1.25.13'
newbin go126;     stub "$BIN" go "go version go1.26 linux/amd64"
run "go1.26 (no patch) = 1.26.0"  1 'VULNERABLE.*go 1.26.0'

newbin mixed;     stub "$BIN" php "PHP 8.3.1 (cli)"; stub "$BIN" go "go version go1.25.1 linux/amd64"
run "vulnerable beats check"      1 'VULNERABLE'

newbin empty
run "nothing installed"           0 'no PHP binary found'
newbin junk;      stub "$BIN" php "not a version"; stub "$BIN" node "garbage"
run "garbage output ignored"      0 'no PHP binary found'

newbin fpm;       stub "$BIN" php "PHP 8.3.36 (cli)"; stub "$BIN" php-fpm "PHP 8.3.20 (fpm-fcgi)"
run "php-fpm checked separately"  1 'VULNERABLE.*php-fpm 8.3.20'
newbin dedupe;    stub "$BIN" php "PHP 8.3.36 (cli)"; ln -s php "$BIN/php8.3"
run "symlink not reported twice"  0 'everything found is patched'
n="$(PATH="$BIN:$TOOLS" PATCHCHECK_SEARCH_DIRS="$BIN" "$BASH" "$ROOT/patchcheck.sh" --no-processes --json | grep -o '"label"' | wc -l | tr -d ' ')"
check "dedupe: php counted once (+node, go = 3 rows)" [ "$n" = 3 ]

newbin quiet;     stub "$BIN" php "PHP 8.3.36 (cli)"; stub "$BIN" node v20.1.0
run "--quiet hides OK lines"      1 'node 20.1.0'                         -q
out="$(PATH="$BIN:$TOOLS" PATCHCHECK_SEARCH_DIRS="$BIN" "$BASH" "$ROOT/patchcheck.sh" -q --no-processes)"
# shellcheck disable=SC2016  # program text is intentionally single-quoted
check "quiet leaked nothing" bash -c '! printf "%s" "$1" | grep -q "php 8.3.36"' _ "$out"

# JSON must be valid
if command -v python3 >/dev/null 2>&1; then
  newbin json; stub "$BIN" php "PHP 8.3.1 (cli)"; stub "$BIN" node v22.23.4
  if PATH="$BIN:$TOOLS:$(dirname "$(command -v python3)")" PATCHCHECK_SEARCH_DIRS="$BIN" "$BASH" "$ROOT/patchcheck.sh" --json --no-processes | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["exit_code"]==1 and d["summary"]["vulnerable"]==1' 2>/dev/null; then
    PASS=$((PASS + 1)); echo "ok   json is valid and correct"
  else
    FAIL=$((FAIL + 1)); echo "FAIL json is valid and correct"
  fi
fi

# stale process: fake /proc with a php-fpm whose binary was replaced
newbin proc; stub "$BIN" php "PHP 8.3.36 (cli)"
mkdir -p "$WORK/proc/4242"; echo php-fpm8.3 > "$WORK/proc/4242/comm"; ln -s "/usr/sbin/php-fpm8.3 (deleted)" "$WORK/proc/4242/exe"
mkdir -p "$WORK/proc/99";   echo bash       > "$WORK/proc/99/comm";   ln -s /bin/bash "$WORK/proc/99/exe"
out="$(PATH="$BIN:$TOOLS" PATCHCHECK_SEARCH_DIRS="$BIN" PATCHCHECK_PROC_DIR="$WORK/proc" "$BASH" "$ROOT/patchcheck.sh" 2>&1)"; rc=$?
if [ "$rc" = 1 ] && printf '%s' "$out" | grep -q 'RESTART.*pid 4242'; then PASS=$((PASS + 1)); echo "ok   stale process detected"; else FAIL=$((FAIL + 1)); echo "FAIL stale process detected"; fi
out="$(PATH="$BIN:$TOOLS" PATCHCHECK_SEARCH_DIRS="$BIN" PATCHCHECK_PROC_DIR="$WORK/proc" "$BASH" "$ROOT/patchcheck.sh" --no-processes 2>&1)"; rc=$?
check "--no-processes skips it" [ "$rc" = 0 ]

# usage errors
BIN="$WORK/bin.empty"
run "unknown flag"                64 'unknown option'                      --bogus
run "missing data file"           64 'not readable'                        --data "$WORK/nope.tsv"
run "--data without value"        64 'needs a file'                        --data
run "--version"                   0  '^patchcheck [0-9]'                   --version

# advisories.tsv sanity: 7 fields per rule, valid statuses, every runtime has older+newer fallbacks
bad="$(awk -F'\t' '!/^#/ && NF && (NF!=7 || $3 !~ /^(fixed|eol|unconfirmed)$/ || ($3=="fixed" && $4=="-"))' "$ROOT/advisories.tsv")"
check "advisories.tsv well-formed${bad:+: $bad}" [ -z "$bad" ]
for rt in php node go; do
  for fb in older newer; do
    # shellcheck disable=SC2016  # awk program is intentionally single-quoted
    check "$rt has '$fb' fallback" awk -F'\t' -v r="$rt" -v f="$fb" '$1==r && $2==f {found=1} END {exit !found}' "$ROOT/advisories.tsv"
  done
done

echo; echo "passed: $PASS  failed: $FAIL"
[ "$FAIL" = 0 ]
