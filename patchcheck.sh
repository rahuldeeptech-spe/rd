#!/usr/bin/env bash
# patchcheck.sh - read-only checker for the Oct 2026 PHP2Shell / Node.js / Go advisories.
# Never modifies the system and makes no network calls. Rules come from advisories.tsv.
#
# Exit codes: 0 all patched | 1 vulnerable or needs restart | 2 manual check needed | 64 usage error
# Works with bash 3.2+ (macOS) and any POSIX awk.

set -u
set -o pipefail

VERSION="1.0.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA="${PATCHCHECK_DATA:-$SCRIPT_DIR/advisories.tsv}"
PROC_DIR="${PATCHCHECK_PROC_DIR:-/proc}"
MANAGER_GLOBS="${PATCHCHECK_MANAGER_GLOBS:-node:$HOME/.nvm/versions/node/*/bin/node node:$HOME/.asdf/installs/nodejs/*/bin/node node:$HOME/.local/share/fnm/node-versions/*/installation/bin/node node:$HOME/.fnm/node-versions/*/installation/bin/node node:$HOME/.volta/tools/image/node/*/bin/node php:$HOME/.phpbrew/php/*/bin/php php:$HOME/.asdf/installs/php/*/bin/php go:$HOME/sdk/go*/bin/go go:$HOME/.asdf/installs/golang/*/go/bin/go go:/usr/local/go/bin/go}"
SEARCH_DIRS="${PATCHCHECK_SEARCH_DIRS:-/usr/sbin /usr/bin /usr/local/sbin /usr/local/bin /opt/remi/*/root/usr/bin /opt/remi/*/root/usr/sbin}"
TAB="$(printf '\t')"

OPT_DOCKER=0
OPT_JSON=0
OPT_QUIET=0
OPT_PROCS=1
OPT_MANAGERS=0
GO_BIN_DIR=""
RESULTS=""
SEEN=""
DATA_UPDATED="unknown"

usage() {
  cat <<EOF
patchcheck $VERSION - read-only PHP / Node.js / Go advisory checker

Usage: patchcheck.sh [options]
  --docker        also check running Docker containers
  --json          machine-readable output
  -q, --quiet     only print problems
  --no-processes  skip the stale-process check (Linux /proc)
  --managers      also check runtimes from nvm, fnm, volta, asdf, phpbrew, ~/sdk/go*
  --go-binaries DIR  scan Go binaries under DIR for the toolchain they were built with (needs go)
  --data FILE     use a different advisories file (default: advisories.tsv next to the script)
  -V, --version   print version
  -h, --help      this help

Exit codes: 0 patched, 1 vulnerable or restart needed, 2 manual check needed, 64 usage error.
EOF
}

die() { echo "patchcheck: $*" >&2; exit 64; }

while [ $# -gt 0 ]; do
  case "$1" in
    --docker) OPT_DOCKER=1 ;;
    --json) OPT_JSON=1 ;;
    -q|--quiet) OPT_QUIET=1 ;;
    --no-processes) OPT_PROCS=0 ;;
    --managers) OPT_MANAGERS=1 ;;
    --go-binaries) [ $# -ge 2 ] || die "--go-binaries needs a directory"; GO_BIN_DIR="$2"; shift ;;
    --data) [ $# -ge 2 ] || die "--data needs a file"; DATA="$2"; shift ;;
    -V|--version) echo "patchcheck $VERSION"; exit 0 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "unknown option: $1" ;;
  esac
  shift
done

[ -r "$DATA" ] || die "advisories file not readable: $DATA"
DATA_UPDATED="$(sed -n 's/^#@ updated //p' "$DATA" | head -n1)"
[ -n "$DATA_UPDATED" ] || DATA_UPDATED="unknown"

# ver_cmp A B -> prints -1, 0 or 1 (numeric, dot-separated)
ver_cmp() {
  awk -v a="$1" -v b="$2" 'BEGIN {
    na = split(a, x, "."); nb = split(b, y, "."); n = (na > nb) ? na : nb
    for (i = 1; i <= n; i++) {
      p = x[i] + 0; q = y[i] + 0
      if (p < q) { print -1; exit }
      if (p > q) { print 1; exit }
    }
    print 0
  }'
}

# branch_of RUNTIME VERSION -> major.minor (php, go) or major (node)
branch_of() {
  case "$1" in
    node) echo "${2%%.*}" ;;
    *) echo "$2" | awk -F. '{print $1 "." $2}' ;;
  esac
}

valid_version() { echo "$1" | grep -Eq '^[0-9]+(\.[0-9]+){1,2}$'; }

# find_rule RUNTIME BRANCH -> sets R_STATUS R_FIXED R_ID R_NOTE ("" if no rule)
find_rule() {
  local rt="$1" br="$2" r b s f i src n maxb="" ex="" old="" new=""
  R_STATUS=""; R_FIXED=""; R_ID=""; R_NOTE=""
  # shellcheck disable=SC2034  # src (source URL) is for humans, unused here
  while IFS="$TAB" read -r r b s f i src n; do
    case "$r" in ''|'#'*) continue ;; esac
    [ "$r" = "$rt" ] || continue
    case "$b" in
      older) old="$s${TAB}$f${TAB}$i${TAB}$n" ;;
      newer) new="$s${TAB}$f${TAB}$i${TAB}$n" ;;
      *)
        if [ -z "$maxb" ] || [ "$(ver_cmp "$b" "$maxb")" = 1 ]; then maxb="$b"; fi
        if [ "$b" = "$br" ]; then ex="$s${TAB}$f${TAB}$i${TAB}$n"; fi
        ;;
    esac
  done < "$DATA"
  local pick="$ex"
  if [ -z "$pick" ]; then
    if [ -n "$maxb" ] && [ "$(ver_cmp "$br" "$maxb")" = 1 ]; then pick="$new"; else pick="$old"; fi
  fi
  [ -n "$pick" ] || return 0
  IFS="$TAB" read -r R_STATUS R_FIXED R_ID R_NOTE <<EOF
$pick
EOF
  [ "$R_FIXED" = "-" ] && R_FIXED=""
  return 0
}

# add_result LABEL RUNTIME VERSION STATE DETAIL ID
add_result() {
  RESULTS="${RESULTS}$1${TAB}$2${TAB}$3${TAB}$4${TAB}$5${TAB}$6
"
}

# evaluate LABEL RUNTIME VERSION
evaluate() {
  local label="$1" rt="$2" v="$3" br state detail
  br="$(branch_of "$rt" "$v")"
  find_rule "$rt" "$br"
  case "$R_STATUS" in
    fixed)
      if [ "$(ver_cmp "$v" "$R_FIXED")" -ge 0 ]; then
        state=OK; detail=">= $R_FIXED"
      else
        state=VULNERABLE; detail="update to >= $R_FIXED"
      fi ;;
    eol) state=VULNERABLE; detail="no upstream fix for this branch. $R_NOTE" ;;
    unconfirmed) state=CHECK; detail="fix not confirmed. $R_NOTE" ;;
    *) state=CHECK; detail="no rule for $rt $br in advisories file" ;;
  esac
  add_result "$label" "$rt" "$v" "$state" "$detail" "$R_ID"
}

# seen_before KEY -> 0 if already recorded, else records it
seen_before() {
  case "$SEEN" in *"|$1|"*) return 0 ;; esac
  SEEN="$SEEN|$1|"
  return 1
}

real_path() { readlink -f "$1" 2>/dev/null || echo "$1"; }

php_version_of() { # php_version_of CMD...
  local out
  out="$("$@" -v 2>/dev/null | head -n1 | sed -E 's/^PHP ([0-9]+\.[0-9]+\.[0-9]+).*/\1/')"
  valid_version "$out" && echo "$out"
}

check_php_binaries() {
  local cands="" d f name v key found=0 c
  for name in php php-cgi php-fpm; do
    c="$(command -v "$name" 2>/dev/null)" && cands="$cands $c"
  done
  for d in $SEARCH_DIRS; do
    for f in "$d"/php "$d"/php[0-9]* "$d"/php-cgi* "$d"/php-fpm*; do
      [ -f "$f" ] && [ -x "$f" ] && cands="$cands $f"
    done
  done
  for f in $cands; do
    v="$(php_version_of "$f")" || continue
    [ -n "$v" ] || continue
    key="php:$(real_path "$f"):$v"
    seen_before "$key" && continue
    found=1
    evaluate "host $(basename "$f")" php "$v"
  done
  [ "$found" = 1 ] || add_result "host php" php "-" "NONE" "no PHP binary found (web PHP may live elsewhere: check php-fpm / mod_php / IIS)" ""
}

node_version_of() { # node_version_of FILE -> version or nothing
  local out
  out="$("$1" -v 2>/dev/null | head -n1 | sed 's/^v//')"
  valid_version "$out" && echo "$out"
}

go_version_of() { # go_version_of FILE -> version (go1.26 is reported as 1.26.0) or nothing
  local out
  out="$("$1" version 2>/dev/null | sed -nE 's/.* go([0-9]+\.[0-9]+(\.[0-9]+)?).*/\1/p' | head -n1)"
  valid_version "$out" || return 0
  [ "$(echo "$out" | tr -cd . | wc -c | tr -d ' ')" = 1 ] && out="$out.0"
  echo "$out"
}

check_node() {
  local f v found=0 name
  for name in node nodejs; do
    f="$(command -v "$name" 2>/dev/null)" || continue
    v="$(node_version_of "$f")"
    [ -n "$v" ] || continue
    seen_before "node:$(real_path "$f"):$v" && continue
    found=1
    evaluate "host $name" node "$v"
  done
  [ "$found" = 1 ] || add_result "host node" node "-" "NONE" "node not found" ""
}

check_go() {
  local f v
  f="$(command -v go 2>/dev/null)" || { add_result "host go" go "-" "NONE" "go not found" ""; return; }
  v="$(go_version_of "$f")"
  [ -n "$v" ] || { add_result "host go" go "-" "NONE" "could not read Go version" ""; return; }
  seen_before "go:$(real_path "$f"):$v" || evaluate "host go" go "$v"
}

# Version managers keep old runtimes in $HOME that are not on PATH but still run (opt-in: --managers).
check_managers() {
  local entry rt pat f v label
  for entry in $MANAGER_GLOBS; do
    rt="${entry%%:*}"; pat="${entry#*:}"
    for f in $pat; do
      if [ ! -f "$f" ] || [ ! -x "$f" ]; then continue; fi
      v=""
      case "$rt" in
        node) v="$(node_version_of "$f")" ;;
        php) v="$(php_version_of "$f")" ;;
        go) v="$(go_version_of "$f")" ;;
      esac
      [ -n "$v" ] || continue
      seen_before "$rt:$(real_path "$f"):$v" && continue
      label="$(printf '%s' "$f" | sed "s#^$HOME#~#")"
      evaluate "manager $label" "$rt" "$v"
    done
  done
}

# A Go binary carries the toolchain it was built with, so upgrading Go does not fix it (opt-in: --go-binaries DIR).
check_go_binaries() {
  local dir="$1" gobin path ver n=0 found
  gobin="$(command -v go 2>/dev/null)" || { add_result "go binaries" go "-" "NONE" "the go toolchain is needed to scan binaries (go version DIR)" ""; return; }
  [ -d "$dir" ] || { add_result "go binaries" go "-" "NONE" "not a directory: $dir" ""; return; }
  found="$("$gobin" version "$dir" 2>/dev/null | sed -nE 's/^(.+): go([0-9]+\.[0-9]+(\.[0-9]+)?)( .*)?$/\1\t\2/p' | head -n 500)"
  while IFS="$TAB" read -r path ver; do
    [ -n "$path" ] || continue
    n=$((n + 1))
    [ "$(echo "$ver" | tr -cd . | wc -c | tr -d ' ')" = 1 ] && ver="$ver.0"
    evaluate "go-binary $path" go "$ver"
  done <<EOF
$found
EOF
  [ "$n" -gt 0 ] || add_result "go binaries" go "-" "NONE" "no Go binaries found under $dir" ""
}

# mod_php runs inside Apache, so no php binary reveals its version.
check_apache_modphp() {
  local c out
  for c in apache2ctl apachectl httpd; do
    command -v "$c" >/dev/null 2>&1 || continue
    out="$("$c" -M 2>/dev/null)" || continue
    if printf '%s' "$out" | grep -Eq 'php[0-9]*_module'; then
      add_result "apache mod_php ($c)" php "-" "CHECK" "mod_php is loaded; its PHP version cannot be read from here. Check the libapache2-mod-php / php package version and restart Apache after upgrading" ""
      return
    fi
  done
}

# A long-running process whose binary was replaced on disk still runs the old, vulnerable code.
check_stale_processes() {
  local p pid comm exe
  [ -d "$PROC_DIR" ] || return 0
  for p in "$PROC_DIR"/[0-9]*; do
    [ -d "$p" ] || continue
    pid="${p##*/}"
    comm="$(cat "$p/comm" 2>/dev/null)" || continue
    case "$comm" in php-fpm*|php-cgi*|apache2|httpd|node|nodejs) ;; *) continue ;; esac
    exe="$(readlink "$p/exe" 2>/dev/null)" || continue
    case "$exe" in
      *" (deleted)")
        add_result "process $comm pid $pid" "$comm" "-" "RESTART" "binary was replaced on disk; restart it to load the patched code" "" ;;
    esac
  done
}

check_docker() {
  local c v f
  if ! command -v docker >/dev/null 2>&1; then
    add_result "docker" docker "-" "NONE" "docker not found" ""; return
  fi
  for c in $(docker ps --format '{{.Names}}' 2>/dev/null); do
    for f in php php-fpm; do
      v="$(docker exec "$c" "$f" -v 2>/dev/null | head -n1 | sed -E 's/^PHP ([0-9]+\.[0-9]+\.[0-9]+).*/\1/')"
      valid_version "$v" && evaluate "container $c $f" php "$v"
    done
    v="$(docker exec "$c" node -v 2>/dev/null | head -n1 | sed 's/^v//')"
    valid_version "$v" && evaluate "container $c node" node "$v"
    v="$(docker exec "$c" go version 2>/dev/null | sed -nE 's/.* go([0-9]+\.[0-9]+(\.[0-9]+)?).*/\1/p' | head -n1)"
    valid_version "$v" && evaluate "container $c go" go "$v"
  done
}

json_str() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'; }

count_state() { printf '%s' "$RESULTS" | awk -F'\t' -v s="$1" '$4 == s {n++} END {print n + 0}'; }

check_php_binaries
check_apache_modphp
check_node
check_go
[ "$OPT_MANAGERS" = 1 ] && check_managers
[ -n "$GO_BIN_DIR" ] && check_go_binaries "$GO_BIN_DIR"
[ "$OPT_PROCS" = 1 ] && check_stale_processes
[ "$OPT_DOCKER" = 1 ] && check_docker

N_BAD=$(( $(count_state VULNERABLE) + $(count_state RESTART) ))
N_CHECK="$(count_state CHECK)"
N_OK="$(count_state OK)"
EXIT=0
[ "$N_CHECK" -gt 0 ] && EXIT=2
[ "$N_BAD" -gt 0 ] && EXIT=1

if [ "$OPT_JSON" = 1 ]; then
  first=1
  printf '{"tool":"patchcheck","version":"%s","data_updated":"%s","results":[' "$VERSION" "$(json_str "$DATA_UPDATED")"
  while IFS="$TAB" read -r label rt v state detail id; do
    [ -n "$label" ] || continue
    [ "$first" = 1 ] || printf ','
    first=0
    printf '{"label":"%s","runtime":"%s","version":"%s","state":"%s","detail":"%s","advisory":"%s"}' \
      "$(json_str "$label")" "$(json_str "$rt")" "$(json_str "$v")" "$state" "$(json_str "$detail")" "$(json_str "$id")"
  done <<EOF
$RESULTS
EOF
  printf '],"summary":{"ok":%s,"vulnerable":%s,"check":%s},"exit_code":%s}\n' "$N_OK" "$N_BAD" "$N_CHECK" "$EXIT"
  exit "$EXIT"
fi

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_OK=$'\033[32m'; C_BAD=$'\033[31m'; C_WARN=$'\033[33m'; C_OFF=$'\033[0m'
else
  C_OK=""; C_BAD=""; C_WARN=""; C_OFF=""
fi

echo "patchcheck $VERSION (advisory data: $DATA_UPDATED)"
while IFS="$TAB" read -r label rt v state detail id; do
  [ -n "$label" ] || continue
  if [ "$OPT_QUIET" = 1 ] && { [ "$state" = OK ] || [ "$state" = NONE ]; }; then continue; fi
  case "$state" in
    OK) col="$C_OK" ;;
    VULNERABLE|RESTART) col="$C_BAD" ;;
    *) col="$C_WARN" ;;
  esac
  idtxt=""; [ -n "$id" ] && idtxt=" [$id]"
  printf '%s%-13s%s %s %s - %s%s\n' "$col" "[$state]" "$C_OFF" "$label" "$v" "$detail" "$idtxt"
done <<EOF
$RESULTS
EOF

echo
case "$EXIT" in
  0) echo "Result: everything found is patched." ;;
  1) echo "Result: ACTION NEEDED. Upgrade, then restart php-fpm / apache / node so the new code loads."
     echo "Distro packages often backport fixes without changing the version number; check the distro"
     echo "changelog (e.g. 'apt changelog php8.3 | grep CVE-2026-109618') before assuming a false alarm." ;;
  2) echo "Result: nothing known-vulnerable, but some versions could not be confirmed. See [CHECK] lines." ;;
esac
exit "$EXIT"
