#!/usr/bin/env bash
# install.sh - download a patchcheck release, verify it, then run it (or keep it).
#
#   bash install.sh [options] [-- patchcheck options]
#
# Examples:
#   bash install.sh                          # latest release: download, verify, run, clean up
#   bash install.sh -- --docker --json       # everything after -- goes to patchcheck.sh
#   bash install.sh --version v1.1.0         # a specific release
#   bash install.sh --install-dir ~/tools    # keep it in ~/tools/patchcheck-v1.1.0 instead of running it
#
# What it checks before anything from the download is executed:
#   1. the tarball's SHA-256 matches the entry in the release's SHA256SUMS (catches corruption and a swapped file)
#   2. if the GitHub CLI (gh) is installed: the build provenance attestation, which proves the tarball was built
#      by this repository's release workflow (catches a swapped file AND a swapped SHA256SUMS)
#   3. the tarball has no absolute paths, no ".." paths and no links
#   4. patchcheck.sh inside reports the version of the tag you asked for
#
# Without gh only step 1 protects you from a tampered download, because the checksum comes from the same place as
# the file. Install gh and run `gh auth login` for the stronger check. Read this file before running it.
#
# Exit codes: patchcheck's own exit code when it ran; 64 usage error; 1 any failed check.
set -euo pipefail

RELEASES_URL="${PATCHCHECK_RELEASES_URL:-https://github.com/rahuldeeptech-spe/rd/releases}"

usage() {
  sed -n '2,/^set -euo/p' "$0" | sed -e '/^set -euo/d' -e 's/^# \{0,1\}//'
}

die() { echo "install.sh: $*" >&2; exit 1; }
usage_error() { echo "install.sh: $*" >&2; echo "Try: bash install.sh --help" >&2; exit 64; }

VERSION=""
INSTALL_DIR=""
ATTEST=auto   # auto | skip | require

while [ $# -gt 0 ]; do
  case "$1" in
    --version) [ $# -ge 2 ] || usage_error "--version needs a value like v1.1.0"; VERSION="$2"; shift ;;
    --install-dir) [ $# -ge 2 ] || usage_error "--install-dir needs a directory"; INSTALL_DIR="$2"; shift ;;
    --no-attestation) ATTEST=skip ;;
    --require-attestation) ATTEST=require ;;
    -h|--help) usage; exit 0 ;;
    --) shift; break ;;
    *) usage_error "unknown option: $1" ;;
  esac
  shift
done

TAG_RE='^v[0-9]+\.[0-9]+\.[0-9]+$'
if [ -n "$VERSION" ] && ! grep -Eq "$TAG_RE" <<<"$VERSION"; then
  usage_error "--version must look like v1.1.0 (got: $VERSION)"
fi

for tool in curl tar awk grep sed mktemp; do
  command -v "$tool" >/dev/null 2>&1 || die "needs $tool"
done

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'
  else die "needs sha256sum or shasum"; fi
}

fetch() { curl --fail --silent --show-error --location --max-time 120 --retry 2 -o "$2" "$1"; }

TAG="$VERSION"
if [ -z "$TAG" ]; then
  final="$(curl --fail --silent --show-error --location --max-time 60 --output /dev/null --write-out '%{url_effective}' "$RELEASES_URL/latest")" \
    || die "could not look up the latest release at $RELEASES_URL/latest"
  TAG="${final##*/}"
  grep -Eq "$TAG_RE" <<<"$TAG" || die "the latest release has an unexpected tag name ($TAG)"
fi

TMP="$(mktemp -d)"
CREATED=""
# shellcheck disable=SC2329  # runs from the EXIT trap
cleanup() {
  local status=$?
  rm -rf "$TMP"
  if [ "$status" != 0 ] && [ -n "$CREATED" ]; then rm -rf "$CREATED"; fi   # never leave a half-installed directory behind
}
trap cleanup EXIT

TARBALL_NAME="patchcheck-$TAG.tar.gz"
TARBALL="$TMP/$TARBALL_NAME"
echo "install.sh: downloading $TAG from $RELEASES_URL"
fetch "$RELEASES_URL/download/$TAG/$TARBALL_NAME" "$TARBALL" || die "could not download $TARBALL_NAME"
fetch "$RELEASES_URL/download/$TAG/SHA256SUMS" "$TMP/SHA256SUMS" || die "could not download SHA256SUMS"

# 1. checksum: exactly one entry for the tarball, and it must match
entries="$(awk -v a="$TARBALL_NAME" -v b="./$TARBALL_NAME" '$2 == a || $2 == b {print $1}' "$TMP/SHA256SUMS")"
[ -n "$entries" ] || die "SHA256SUMS has no entry for $TARBALL_NAME"
[ "$(printf '%s\n' "$entries" | wc -l | tr -d ' ')" = 1 ] || die "SHA256SUMS has more than one entry for $TARBALL_NAME"
grep -Eq '^[0-9a-f]{64}$' <<<"$entries" || die "SHA256SUMS has a malformed entry for $TARBALL_NAME"
actual="$(sha256_of "$TARBALL")"
[ "$actual" = "$entries" ] || die "CHECKSUM MISMATCH for $TARBALL_NAME (expected $entries, got $actual). Nothing was run."
echo "install.sh: checksum OK"

# 2. attestation
if [ "$ATTEST" != skip ]; then
  slug="$(printf '%s' "$RELEASES_URL" | sed -nE 's#^https://github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/releases/?$#\1#p')"
  if ! command -v gh >/dev/null 2>&1; then
    [ "$ATTEST" != require ] || die "--require-attestation needs the GitHub CLI (gh)"
    echo "install.sh: WARNING attestation not checked (install gh for the stronger check; the checksum above only proves the download matches the release page)" >&2
  elif [ -z "$slug" ]; then
    [ "$ATTEST" != require ] || die "--require-attestation works only with a github.com releases URL"
    echo "install.sh: WARNING attestation not checked (not a github.com releases URL)" >&2
  else
    if out="$(gh attestation verify "$TARBALL" --repo "$slug" 2>&1)"; then
      echo "install.sh: attestation OK (built by $slug)"
    else
      printf '%s\n' "$out" >&2
      die "ATTESTATION VERIFICATION FAILED for $TARBALL_NAME. Nothing was run. If you are not logged in to gh, run 'gh auth login'. Releases made before attestations were added have none; use --no-attestation to accept the checksum only."
    fi
  fi
fi

# 3. the archive must not escape its directory
# (here-strings, not pipes: with pipefail a pipe into grep -q can report failure when grep matched, and the check would be skipped)
listing="$(tar -tzf "$TARBALL")" || die "the download is not a readable tar.gz archive"
verbose="$(tar -tvzf "$TARBALL")" || die "the download is not a readable tar.gz archive"
if grep -Eq '^/|(^|/)\.\.(/|$)' <<<"$listing"; then die "the archive contains an absolute or '..' path. Nothing was run."; fi
if grep -Eq '^[lh]' <<<"$verbose"; then die "the archive contains a link. Nothing was run."; fi

if [ -n "$INSTALL_DIR" ]; then
  DEST="$INSTALL_DIR/patchcheck-$TAG"
  [ ! -e "$DEST" ] || die "$DEST already exists; remove it or pick another --install-dir"
  mkdir -p "$DEST"
  CREATED="$DEST"
else
  DEST="$TMP/extracted"
  mkdir -p "$DEST"
fi
tar -xzf "$TARBALL" -C "$DEST" --no-same-owner

# 4. the version inside must be the version asked for
[ -f "$DEST/patchcheck.sh" ] && [ -f "$DEST/advisories.tsv" ] || die "the archive does not contain patchcheck.sh and advisories.tsv"
inside="$(bash "$DEST/patchcheck.sh" --version 2>/dev/null || true)"
[ "$inside" = "patchcheck ${TAG#v}" ] || die "version mismatch: the archive says '$inside' but the release is $TAG"

if [ -n "$INSTALL_DIR" ]; then
  echo "install.sh: installed to $DEST"
  echo "install.sh: run it with:  bash $DEST/patchcheck.sh"
  exit 0
fi

echo "install.sh: running patchcheck $TAG"
echo
rc=0
bash "$DEST/patchcheck.sh" "$@" || rc=$?
exit "$rc"
