#!/usr/bin/env bash
# check-php2shell.sh - read-only checker for PHP2Shell (CVE-2026-109618 / CVE-2026-109619)
# and the Oct 21 2026 Node.js security release. Does not change anything on the system.
#
# Usage:  ./check-php2shell.sh            # check php / node on this host
#         ./check-php2shell.sh --docker   # also check running Docker containers
#
# Exit code: 0 = everything found is patched, 1 = vulnerable/EOL/unknown found.

set -u

# Minimum patched versions per branch (from the PHP and Node.js advisories).
PHP_FIXED="8.5:8.5.12 8.4:8.4.27 8.3:8.3.36 8.2:8.2.35"
NODE_FIXED="26:26.12.1 24:24.22.1 22:22.23.4"

RC=0

ver_ge() { # ver_ge A B -> true if A >= B
  [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" = "$2" ]
}

lookup() { # lookup "k:v k:v" key
  for pair in $1; do
    [ "${pair%%:*}" = "$2" ] && { echo "${pair#*:}"; return 0; }
  done
  return 1
}

report() { # report <label> <version> <fixed-or-empty> <extra>
  local label="$1" v="$2" fixed="$3" extra="$4"
  if [ -z "$fixed" ]; then
    echo "[VULNERABLE/EOL] $label $v - no upstream fix for this branch. $extra"
    RC=1
  elif ver_ge "$v" "$fixed"; then
    echo "[OK]             $label $v (>= $fixed)"
  else
    echo "[VULNERABLE]     $label $v - update to >= $fixed"
    RC=1
  fi
}

check_php() { # check_php <label> <version>
  local label="$1" v="$2" branch fixed=""
  branch="${v%.*}"
  if fixed="$(lookup "$PHP_FIXED" "$branch")"; then
    report "$label PHP" "$v" "$fixed" ""
  elif ver_ge "$branch" "8.6"; then
    echo "[CHECK]          $label PHP $v - newer than the branches in this script; confirm against the PHP advisory."
    RC=1
  else
    report "$label PHP" "$v" "" "Upgrade to a supported branch or build the source-level backport. Distro packages may carry a backport without changing the version number; check your distro's changelog."
  fi
}

check_node() { # check_node <label> <version>
  local label="$1" v="$2" major fixed=""
  major="${v%%.*}"
  if fixed="$(lookup "$NODE_FIXED" "$major")"; then
    report "$label Node" "$v" "$fixed" ""
  elif [ "$major" -gt 26 ] 2>/dev/null; then
    echo "[CHECK]          $label Node $v - newer than the branches in this script; confirm against the Node.js advisory."
    RC=1
  else
    report "$label Node" "$v" "" "End-of-life branch; move to 22, 24 or 26."
  fi
}

echo "== Host =="
if command -v php >/dev/null 2>&1; then
  check_php "host" "$(php -r 'echo PHP_VERSION;' | sed 's/[^0-9.].*//')"
else
  echo "[--]             php CLI not found (web PHP may still be installed: check php-fpm / mod_php)"
fi
command -v php-fpm >/dev/null 2>&1 && check_php "host php-fpm" "$(php-fpm -v | head -n1 | sed -E 's/^PHP ([0-9.]+).*/\1/')"
if command -v node >/dev/null 2>&1; then
  check_node "host" "$(node -v | sed 's/^v//')"
else
  echo "[--]             node not found"
fi

if [ "${1:-}" = "--docker" ]; then
  echo "== Docker containers =="
  if command -v docker >/dev/null 2>&1; then
    for c in $(docker ps --format '{{.Names}}'); do
      pv="$(docker exec "$c" php -r 'echo PHP_VERSION;' 2>/dev/null | sed 's/[^0-9.].*//')"
      [ -n "$pv" ] && check_php "container $c" "$pv"
      nv="$(docker exec "$c" node -v 2>/dev/null | sed 's/^v//')"
      [ -n "$nv" ] && check_node "container $c" "$nv"
    done
  else
    echo "[--]             docker not found"
  fi
fi

echo
if [ "$RC" -eq 0 ]; then
  echo "Result: everything checked is patched."
else
  echo "Result: action needed. After upgrading, restart php-fpm / apache / node processes."
fi
exit "$RC"
