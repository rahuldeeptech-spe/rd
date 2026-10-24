#!/usr/bin/env bash
# Tests for install.sh. A stub curl serves a fake release from a local folder; a stub gh stands in for the GitHub CLI.
# Nothing touches the network.
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
PASS=0; FAIL=0
VER="$(sed -n 's/^VERSION="\(.*\)"/\1/p' "$ROOT/patchcheck.sh")"
TAG="v$VER"

check() { local name="$1"; shift; if "$@"; then PASS=$((PASS + 1)); echo "ok   $name"; else FAIL=$((FAIL + 1)); echo "FAIL $name"; fi; }

# a PATH that holds only what install.sh needs, plus the stubs
TOOLS="$WORK/tools"; mkdir -p "$TOOLS"
for t in bash awk grep sed mktemp tar tr wc cat rm mkdir dirname basename sha256sum head sort date cut touch find python3 cp gzip gunzip; do
  p="$(command -v "$t")" && ln -sf "$p" "$TOOLS/$t"
done
cat > "$TOOLS/curl" <<'CEOF'
#!/bin/sh
# stub curl: understands  -o FILE URL  and  --output /dev/null --write-out %{url_effective} URL
out=""; write=""; url=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o|--output) out="$2"; shift ;;
    -w|--write-out) write="$2"; shift ;;
    --max-time|--retry) shift ;;
    -*) ;;
    *) url="$1" ;;
  esac
  shift
done
echo "$url" >> "$STUB_LOG"
case "$url" in
  */latest) [ -n "$write" ] && printf '%s' "$STUB_LATEST_URL"; exit 0 ;;
  */download/*) f="$STUB_ROOT/download/${url#*/download/}"; [ -f "$f" ] || exit 22; if [ -n "$out" ]; then cp "$f" "$out" || exit 23; fi; exit 0 ;;
esac
exit 22
CEOF
chmod +x "$TOOLS/curl"
cat > "$WORK/gh" <<'GEOF'
#!/bin/sh
echo "gh $*" >> "$STUB_LOG"
if [ "$1 $2" = "attestation verify" ]; then
  if [ -n "${STUB_GH_FAIL:-}" ]; then echo "error: no attestations found" >&2; exit 1; fi
  echo "Loaded digest sha256:abc for file://$3"; exit 0
fi
exit 0
GEOF
chmod +x "$WORK/gh"

# build a fake release for $TAG from the real files, with a canary that proves whether patchcheck.sh ran
make_release() { # make_release NAME  -> $WORK/rel/NAME/download/$TAG/{tarball,SHA256SUMS}
  local name="$1" d="$WORK/rel/$1/download/$TAG" src="$WORK/src.$1"
  rm -rf "$src" "$WORK/rel/$name"; mkdir -p "$d" "$src/monitor"
  cp "$ROOT/patchcheck.sh" "$ROOT/advisories.tsv" "$src/"; cp "$ROOT/monitor/monitor.py" "$src/monitor/"
  printf 'ok\n' > "$src/README.md"
  tar czf "$d/patchcheck-$TAG.tar.gz" -C "$src" .
  ( cd "$d" && sha256sum "./patchcheck-$TAG.tar.gz" > SHA256SUMS )
  echo "$d"
}
canary_release() { # same, but patchcheck.sh drops a marker file when it runs, so we can tell it must not have run
  local d; d="$(make_release "$1")"; local src="$WORK/src.$1"
  # shellcheck disable=SC2016  # the generated script must keep its own $1 and $@
  printf '#!/bin/bash\n[ "$1" = "--version" ] && { echo "patchcheck %s"; exit 0; }\ntouch "%s/RAN"\necho ran "$@"\nexit 3\n' "$VER" "$WORK" > "$src/patchcheck.sh"
  tar czf "$d/patchcheck-$TAG.tar.gz" -C "$src" .
  ( cd "$d" && sha256sum "./patchcheck-$TAG.tar.gz" > SHA256SUMS )
  echo "$d"
}

run() { # run NAME [install.sh args]   (env: WITH_GH=1 puts the gh stub on PATH)
  local name="$1"; shift
  local path="$TOOLS"; [ -n "${WITH_GH:-}" ] && { mkdir -p "$WORK/ghbin"; cp "$WORK/gh" "$WORK/ghbin/gh"; path="$TOOLS:$WORK/ghbin"; }
  : > "$STUB_LOG"; rm -f "$WORK/RAN"
  mkdir -p "$WORK/tmpdir"
  OUT="$(TMPDIR="$WORK/tmpdir" STUB_ROOT="$WORK/rel/$name" STUB_LOG="$STUB_LOG" STUB_LATEST_URL="${STUB_LATEST_URL:-https://github.com/rahuldeeptech-spe/rd/releases/tag/$TAG}" \
         PATH="$path" PATCHCHECK_RELEASES_URL="${RELEASES_URL:-https://github.com/rahuldeeptech-spe/rd/releases}" \
         "$TOOLS/bash" "$ROOT/install.sh" "$@" 2>&1)"; RC=$?
}
export STUB_LOG="$WORK/stub.log"
out_has() { grep -q -- "$1" <<<"$OUT"; }
out_lacks() { ! grep -q -- "$1" <<<"$OUT"; }
rc_is() { [ "$RC" = "$1" ]; }
rc_not0() { [ "$RC" != 0 ]; }
gh_called() { grep -q 'gh ' "$STUB_LOG"; }
gh_not_called() { ! grep -q 'gh ' "$STUB_LOG"; }
stub_log_empty() { [ ! -s "$STUB_LOG" ]; }
ran() { [ -e "$WORK/RAN" ]; }
not_ran() { [ ! -e "$WORK/RAN" ]; }

# ---- happy paths (the real patchcheck.sh) ----
make_release real >/dev/null
run real --version "$TAG" --no-attestation -- --version
check "explicit version: exit 0" rc_is 0
check "explicit version: runs the real patchcheck.sh" out_has "patchcheck $VER"
check "explicit version: checksum is reported OK" out_has "checksum OK"

run real --no-attestation -- --version
check "latest: exit 0" rc_is 0
check "latest: resolves the tag from the redirect and runs" out_has "running patchcheck $TAG"

run real --version "$TAG" --no-attestation -- --bogus-flag
check "patchcheck's own exit code is passed through (64 for a bad flag)" rc_is 64

run real --version "$TAG" --no-attestation -- --no-processes --json
check "arguments after -- reach patchcheck.sh" out_has '"tool":"patchcheck"'

# ---- tampering: the canary must never run ----
d="$(canary_release canary)"
run canary --version "$TAG" --no-attestation
check "canary release itself works when untouched (control)" rc_is 3
check "control: the canary does run on a valid release" ran

d="$(canary_release tamper)"; printf 'x' >> "$d/patchcheck-$TAG.tar.gz"
run tamper --version "$TAG" --no-attestation
check "tampered tarball: fails" rc_not0
check "tampered tarball: says CHECKSUM MISMATCH" out_has "CHECKSUM MISMATCH"
check "tampered tarball: nothing was executed" not_ran

d="$(canary_release swapsums)"; echo "0000000000000000000000000000000000000000000000000000000000000000  ./patchcheck-$TAG.tar.gz" > "$d/SHA256SUMS"
run swapsums --version "$TAG" --no-attestation
check "wrong checksum entry: fails" rc_not0
check "wrong checksum entry: not executed" not_ran

d="$(canary_release nosum)"; echo "$(sha256sum "$d/patchcheck-$TAG.tar.gz" | cut -d' ' -f1)  ./something-else.tar.gz" > "$d/SHA256SUMS"
run nosum --version "$TAG" --no-attestation
check "no entry for the tarball: fails" rc_not0
check "no entry: not executed" not_ran
check "no entry: says so" out_has "no entry for"

d="$(canary_release dup)"; h="$(sha256sum "$d/patchcheck-$TAG.tar.gz" | cut -d' ' -f1)"; printf '%s  ./patchcheck-%s.tar.gz\n%s  ./patchcheck-%s.tar.gz\n' "$h" "$TAG" "$h" "$TAG" > "$d/SHA256SUMS"
run dup --version "$TAG" --no-attestation
check "two entries for the tarball: refused (ambiguous)" rc_not0
check "two entries: not executed" not_ran

d="$(canary_release missing)"; rm "$d/SHA256SUMS"
run missing --version "$TAG" --no-attestation
check "SHA256SUMS missing: fails" rc_not0
check "SHA256SUMS missing: not executed" not_ran

# valid checksum but a hostile archive
hostile() { # hostile NAME PYTHON_SNIPPET_USING_tf
  local d; d="$(canary_release "$1")"
  python3 - "$d/patchcheck-$TAG.tar.gz" "$2" <<'PYEOF'
import sys,tarfile,io
path,kind=sys.argv[1],sys.argv[2]
with tarfile.open(path,"w:gz") as tf:
    data=b"echo pwned\n"
    ti=tarfile.TarInfo({"dotdot":"../evil.sh","abs":"/tmp/evil.sh","sub":"a/../../evil.sh","link":"patchcheck.sh"}[kind]); ti.size=len(data)
    if kind=="link":
        ti.type=tarfile.SYMTYPE; ti.linkname="/etc/passwd"; ti.size=0; tf.addfile(ti)
    else: tf.addfile(ti,io.BytesIO(data))
PYEOF
  ( cd "$d" && sha256sum "./patchcheck-$TAG.tar.gz" > SHA256SUMS )
}
for kind in dotdot abs sub link; do
  hostile "h-$kind" "$kind"
  run "h-$kind" --version "$TAG" --no-attestation
  check "hostile archive ($kind) with a VALID checksum: refused" rc_not0
  check "hostile archive ($kind): nothing executed" not_ran
  check "hostile archive ($kind): checksum itself was fine" out_has "checksum OK"
  if [ "$kind" = link ]; then check "hostile archive ($kind): refused for the right reason" out_has "contains a link"
  else check "hostile archive ($kind): refused for the right reason" out_has "absolute or '..' path"; fi
done
check "hostile archive: nothing was written outside the temp dir" bash -c "[ ! -e '$WORK/rel/h-dotdot/evil.sh' ] && [ ! -e /tmp/evil.sh ]"

d="$(make_release oldver)"; src="$WORK/src.oldver"; sed -i 's/^VERSION=".*"/VERSION="0.0.1"/' "$src/patchcheck.sh"
tar czf "$d/patchcheck-$TAG.tar.gz" -C "$src" .; ( cd "$d" && sha256sum "./patchcheck-$TAG.tar.gz" > SHA256SUMS )
run oldver --version "$TAG" --no-attestation
check "version inside differs from the tag: refused" rc_not0
check "version mismatch: says so" out_has "version mismatch"

d="$(make_release incomplete)"; src="$WORK/src.incomplete"; rm "$src/advisories.tsv"
tar czf "$d/patchcheck-$TAG.tar.gz" -C "$src" .; ( cd "$d" && sha256sum "./patchcheck-$TAG.tar.gz" > SHA256SUMS )
run incomplete --version "$TAG" --no-attestation
check "archive without advisories.tsv: refused" rc_not0

# ---- arguments ----
for bad in "1.0.0" "v1.0" "v1.0.0-rc1" 'v1.0.0; touch /tmp/pwn' '../v1.0.0'; do
  run real --version "$bad" --no-attestation
  check "bad --version '$bad': usage error 64" rc_is 64
  check "bad --version '$bad': nothing downloaded" stub_log_empty
done
run real --bogus
check "unknown option: 64" rc_is 64
run real --version
check "--version without a value: 64" rc_is 64
STUB_LATEST_URL="https://github.com/rahuldeeptech-spe/rd/releases/tag/not-a-version" run real --no-attestation
check "latest resolves to junk: refused" rc_not0
check "latest junk: says unexpected tag" out_has "unexpected tag"
run real --version v9.9.9 --no-attestation
check "release that does not exist: fails cleanly" rc_not0
check "missing release: says could not download" out_has "could not download"
run real --help
check "--help exits 0" rc_is 0
check "--help prints usage" out_has "install.sh"

# ---- --install-dir ----
rm -rf "$WORK/inst"; run real --version "$TAG" --no-attestation --install-dir "$WORK/inst"
check "--install-dir: exit 0" rc_is 0
check "--install-dir: files are there" test -f "$WORK/inst/patchcheck-$TAG/patchcheck.sh"
check "--install-dir: does not run it" out_lacks "running patchcheck"
run real --version "$TAG" --no-attestation --install-dir "$WORK/inst"
check "--install-dir: refuses to overwrite an existing install" rc_not0
check "overwrite refusal says already exists" out_has "already exists"
rm -rf "$WORK/inst2"; run oldver --version "$TAG" --no-attestation --install-dir "$WORK/inst2"
check "--install-dir: a failed check fails" rc_not0
check "--install-dir: and leaves no half-installed directory" test ! -e "$WORK/inst2/patchcheck-$TAG"

# ---- attestation ----
d="$(canary_release att)"
WITH_GH=1 run att --version "$TAG"
check "gh present and verify OK: proceeds and runs" rc_is 3
check "gh OK: reports attestation OK" out_has "attestation OK"
check "gh OK: verify called with --repo owner/name" grep -q "attestation verify .* --repo rahuldeeptech-spe/rd" "$STUB_LOG"
WITH_GH=1 STUB_GH_FAIL=1 run att --version "$TAG"
check "gh verify FAILS: refused" rc_not0
check "gh fails: not executed" not_ran
check "gh fails: says ATTESTATION VERIFICATION FAILED" out_has "ATTESTATION VERIFICATION FAILED"
check "gh fails: shows gh's own error" out_has "no attestations found"
WITH_GH=1 STUB_GH_FAIL=1 run att --version "$TAG" --no-attestation
check "--no-attestation skips a failing gh" rc_is 3
check "--no-attestation: gh never called" gh_not_called
run att --version "$TAG"
check "no gh, default mode: still runs" rc_is 3
check "no gh: the warning is printed" out_has "attestation not checked"
run att --version "$TAG" --require-attestation
check "--require-attestation without gh: refused" rc_not0
check "require + no gh: not executed" not_ran
RELEASES_URL="https://example.test/releases" WITH_GH=1 run att --version "$TAG" --require-attestation
check "--require-attestation with a non-GitHub URL: refused" rc_not0
check "require + non-GitHub: not executed" not_ran

# ---- cleanup: every run above used its own TMPDIR, which must be empty again ----
check "no temp directories left behind by any run (success or failure)" test -z "$(ls -A "$WORK/tmpdir")"

echo; echo "passed: $PASS  failed: $FAIL"
[ "$FAIL" = 0 ]
