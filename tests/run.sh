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
n="$(PATH="$BIN:$TOOLS" PATCHCHECK_SEARCH_DIRS="$BIN" "$BASH" "$ROOT/patchcheck.sh" --no-processes --json | grep -o '"label":"host php[^"]*"' | wc -l | tr -d ' ')"
check "dedupe: php (and its php8.3 symlink) counted once" [ "$n" = 1 ]

newbin quiet;     stub "$BIN" php "PHP 8.3.36 (cli)"; stub "$BIN" node v20.1.0
run "--quiet hides OK lines"      1 'node 20.1.0'                         -q
out="$(PATH="$BIN:$TOOLS" PATCHCHECK_SEARCH_DIRS="$BIN" "$BASH" "$ROOT/patchcheck.sh" -q --no-processes)"
# shellcheck disable=SC2016  # program text is intentionally single-quoted
check "quiet leaked nothing" bash -c '! printf "%s" "$1" | grep -q "php 8.3.36"' _ "$out"

# JSON must be valid
if command -v python3 >/dev/null 2>&1; then
  newbin json; stub "$BIN" php "PHP 8.3.1 (cli)"; stub "$BIN" node v22.23.4
  # patchcheck runs on the hermetic PATH only; python3 reads its output from the pipe with the normal PATH.
  if PATH="$BIN:$TOOLS" PATCHCHECK_SEARCH_DIRS="$BIN" "$BASH" "$ROOT/patchcheck.sh" --json --no-processes | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["exit_code"]==1 and d["summary"]["vulnerable"]==1' 2>/dev/null; then
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

# --managers: runtimes that are not on PATH
newbin mgr; stub "$BIN" php "PHP 8.3.36 (cli)"
MG="$WORK/home/.nvm/versions/node"; mkdir -p "$MG/v20.1.0/bin" "$MG/v24.22.1/bin"
stub "$MG/v20.1.0/bin" node v20.1.0; stub "$MG/v24.22.1/bin" node v24.22.1
export PATCHCHECK_MANAGER_GLOBS="node:$MG/*/bin/node"
run "managers: ignored unless asked"   0 'everything found is patched'
run "managers: old node is reported"   1 'VULNERABLE.*manager .*v20\.1\.0/bin/node 20\.1\.0' --managers
run "managers: patched node is OK"     1 'OK.*manager .*v24\.22\.1/bin/node 24\.22\.1' --managers
unset PATCHCHECK_MANAGER_GLOBS

# --go-binaries: the toolchain baked into a built binary
newbin gob
cat > "$BIN/go" <<'GOEOF'
#!/bin/sh
if [ "$#" -eq 1 ]; then echo "go version go1.26.10 linux/amd64"; else printf '%s\n' "$2/app: go1.24.7" "$2/tool: go1.26.10 X:boringcrypto"; fi
GOEOF
chmod +x "$BIN/go"; mkdir -p "$WORK/gobins"
run "go-binaries: old toolchain flagged"  2 'CHECK.*go-binary .*/app 1\.24\.7'    --go-binaries "$WORK/gobins"
run "go-binaries: patched one is OK"      2 'OK.*go-binary .*/tool 1\.26\.10'     --go-binaries "$WORK/gobins"
run "go-binaries: not a directory"        0 'not a directory'                       --go-binaries "$WORK/nope"
newbin gob2; printf '#!/bin/sh\nif [ "$#" -eq 1 ]; then echo "go version go1.26.10 linux/amd64"; fi\n' > "$BIN/go"; chmod +x "$BIN/go"
run "go-binaries: none found"             0 'no Go binaries found'                  --go-binaries "$WORK/gobins"
newbin gob3
run "go-binaries: needs go itself"        0 'toolchain is needed'                   --go-binaries "$WORK/gobins"

# Apache mod_php hides its version from every binary
newbin mp;  stub "$BIN" php "PHP 8.3.36 (cli)"; printf '#!/bin/sh\necho " php_module (shared)"\n' > "$BIN/apachectl"; chmod +x "$BIN/apachectl"
run "mod_php loaded -> manual check"      2 'CHECK.*apache mod_php'
newbin mp2; stub "$BIN" php "PHP 8.3.36 (cli)"; printf '#!/bin/sh\necho " core_module (static)"\n' > "$BIN/apachectl"; chmod +x "$BIN/apachectl"
run "apache without php stays quiet"      0 'everything found is patched'

# --- Python Brotli packages (Node2Shell, CVE-2026-111497)
pystub() { # pystub DIR NAME: answers like importlib.metadata.version() from STUB_BROTLI / STUB_BROTLICFFI
  cat > "$1/$2" <<'PYSTUB'
#!/bin/sh
for last; do :; done
case "$last" in
  brotli) if [ -n "${STUB_BROTLI:-}" ]; then echo "$STUB_BROTLI"; exit 0; fi ;;
  brotlicffi) if [ -n "${STUB_BROTLICFFI:-}" ]; then echo "$STUB_BROTLICFFI"; exit 0; fi ;;
esac
exit 1
PYSTUB
  chmod +x "$1/$2"
}
newbin py1; pystub "$BIN" python3
STUB_BROTLI=1.2.1 run "pip brotli 1.2.1 (patched)"          0 'OK.*package brotli 1\.2\.1'
STUB_BROTLI=1.2.0 run "pip brotli 1.2.0 (one behind)"       1 'VULNERABLE.*package brotli 1\.2\.0.*>= 1\.2\.1'
STUB_BROTLI=1.1.0 run "pip brotli 1.1.0 (no 1.1.x fix)"     1 'VULNERABLE.*package brotli 1\.1\.0.*no upstream fix'
STUB_BROTLI=1.0.9 run "pip brotli 1.0.9"                    1 'VULNERABLE.*package brotli 1\.0\.9'
STUB_BROTLI=1.3.0 run "pip brotli newer than the data"      2 'CHECK.*package brotli 1\.3\.0'
STUB_BROTLICFFI=1.2.0.0 run "pip brotlicffi 1.2.0.0 (four-part version)" 1 'VULNERABLE.*package brotlicffi 1\.2\.0\.0.*>= 1\.2\.1\.0'
STUB_BROTLICFFI=1.2.1.0 run "pip brotlicffi 1.2.1.0 (patched)"           0 'OK.*package brotlicffi 1\.2\.1\.0'
STUB_BROTLI=1.2.1 STUB_BROTLICFFI=1.1.0.0 run "both packages are reported independently" 1 'VULNERABLE.*brotlicffi 1\.1\.0\.0'
run "python without the packages: silent and fine"          0 'everything found is patched'
newbin py0
run "no python at all: a NONE row, not a failure"           0 'no python found'
newbin py2; pystub "$BIN" python3; mkdir -p "$WORK/venv/bin"; pystub "$WORK/venv/bin" python
STUB_BROTLI=1.2.1 run "--python adds a virtualenv's python"  0 'package brotli 1\.2\.1' --python "$WORK/venv/bin/python"
n="$(STUB_BROTLI=1.2.0 PATH="$BIN:$TOOLS" PATCHCHECK_SEARCH_DIRS="$BIN" "$BASH" "$ROOT/patchcheck.sh" --no-processes --json --python "$WORK/venv/bin/python" --python "$WORK/venv/bin/python" | grep -o '"label":"python [^"]*package brotli"' | wc -l | tr -d ' ')"
check "--python given twice (and the PATH python): each interpreter counted once" [ "$n" = 2 ]
run "--python nonexistent: reported, no crash"               0 'not an executable file' --python "$WORK/nope/python"
run "--python without a value: usage error"                  64 'needs the path' --python
( cd "$WORK/venv" && STUB_BROTLI=1.2.0 PATH="$BIN:$TOOLS" PATCHCHECK_SEARCH_DIRS="$BIN" "$BASH" "$ROOT/patchcheck.sh" --no-processes --python bin/python > "$WORK/rel.out" 2>&1 )
check "--python with a relative path is resolved" grep -q 'package brotli 1.2.0' "$WORK/rel.out"

# a hostile directory must never get code executed: run the REAL python from a folder containing a fake importlib
if command -v python3 >/dev/null 2>&1; then
  newbin py3; ln -s "$(command -v python3)" "$BIN/python3"
  mkdir -p "$WORK/evil/importlib"; printf 'import os\nopen(os.environ["EVIL_MARKER"], "w").close()\n' > "$WORK/evil/importlib/__init__.py"
  rm -f "$WORK/evil.marker"
  ( cd "$WORK/evil" && EVIL_MARKER="$WORK/evil.marker" PATH="$BIN:$TOOLS" PATCHCHECK_SEARCH_DIRS="$BIN" "$BASH" "$ROOT/patchcheck.sh" --no-processes > "$WORK/evil.out" 2>&1 )
  check "hostile cwd: a fake importlib in the current directory is never imported" test ! -e "$WORK/evil.marker"
  ( cd "$WORK/evil" && PYTHONPATH="$WORK/evil" EVIL_MARKER="$WORK/evil.marker" PATH="$BIN:$TOOLS" PATCHCHECK_SEARCH_DIRS="$BIN" "$BASH" "$ROOT/patchcheck.sh" --no-processes > "$WORK/evil.out" 2>&1 )
  check "hostile PYTHONPATH is ignored" test ! -e "$WORK/evil.marker"
fi

# a REAL virtualenv (no stub, no network): its bin/python is a symlink to the base interpreter and must still be checked
if command -v python3 >/dev/null 2>&1 && python3 -m venv --without-pip "$WORK/realvenv" >/dev/null 2>&1; then
  site="$("$WORK/realvenv/bin/python" -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')"
  fakepkg() { mkdir -p "$site/$1.dist-info"; printf 'Metadata-Version: 2.1\nName: %s\nVersion: %s\n' "$1" "$2" > "$site/$1.dist-info/METADATA"; }
  newbin rv; ln -s "$(command -v python3)" "$BIN/python3"
  fakepkg Brotli 1.2.0
  run "real venv with Brotli 1.2.0: vulnerable"             1 'VULNERABLE.*realvenv/bin/python package brotli 1\.2\.0' --python "$WORK/realvenv/bin/python"
  rm -rf "$site/Brotli.dist-info"; fakepkg Brotli 1.2.1
  run "real venv with Brotli 1.2.1: ok (not mistaken for the system python)" 0 'OK.*realvenv/bin/python package brotli 1\.2\.1' --python "$WORK/realvenv/bin/python"
  rm -rf "$site/Brotli.dist-info"; fakepkg brotlicffi 1.2.0.0
  run "real venv with brotlicffi 1.2.0.0: vulnerable"       1 'VULNERABLE.*package brotlicffi 1\.2\.0\.0' --python "$WORK/realvenv/bin/python"
  rm -rf "$site/brotlicffi.dist-info"
  run "real venv without the packages: nothing reported"    0 'everything found is patched' --python "$WORK/realvenv/bin/python"
fi

# python packages inside running containers
newbin dk
# shellcheck disable=SC2016  # the generated stub must keep its own $1 and $@
printf '#!/bin/sh\ncase "$1" in\n  ps) echo web ;;\n  exec) for last; do :; done; if [ "$3 $last" = "python3 brotli" ]; then echo 1.2.0; exit 0; fi; exit 1 ;;\nesac\n' > "$BIN/docker"; chmod +x "$BIN/docker"
run "--docker: python packages inside a container"          1 'VULNERABLE.*container web python3 package brotli 1\.2\.0' --docker

# usage errors
BIN="$WORK/bin.empty"
run "unknown flag"                64 'unknown option'                      --bogus
run "missing data file"           64 'not readable'                        --data "$WORK/nope.tsv"
run "--data without value"        64 'needs a file'                        --data
run "--version"                   0  '^patchcheck [0-9]'                   --version
run "--go-binaries without value" 64 'needs a directory'                    --go-binaries

# advisories.tsv sanity: 7 fields per rule, valid statuses, every runtime has older+newer fallbacks
bad="$(awk -F'\t' '!/^#/ && NF && (NF!=7 || $3 !~ /^(fixed|eol|unconfirmed)$/ || ($3=="fixed" && $4=="-"))' "$ROOT/advisories.tsv")"
check "advisories.tsv well-formed${bad:+: $bad}" [ -z "$bad" ]
for rt in php node go brotli brotlicffi; do
  for fb in older newer; do
    # shellcheck disable=SC2016  # awk program is intentionally single-quoted
    check "$rt has '$fb' fallback" awk -F'\t' -v r="$rt" -v f="$fb" '$1==r && $2==f {found=1} END {exit !found}' "$ROOT/advisories.tsv"
  done
done

echo; echo "passed: $PASS  failed: $FAIL"
[ "$FAIL" = 0 ]
