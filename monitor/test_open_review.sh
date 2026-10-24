#!/usr/bin/env bash
# Tests for open_review.sh with a stub gh and a local bare repository as "origin". No network.
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$HERE/open_review.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
PASS=0; FAIL=0

check() { # check NAME CMD...
  local name="$1"; shift
  if "$@"; then PASS=$((PASS + 1)); echo "ok   $name"; else FAIL=$((FAIL + 1)); echo "FAIL $name"; fi
}
logged() { grep -q -- "$1" "$GH_LOG"; }
not_logged() { ! grep -q -- "$1" "$GH_LOG"; }

mkdir -p "$WORK/bin"
cat > "$WORK/bin/gh" <<'GHEOF'
#!/bin/sh
echo "gh $*" >> "$GH_LOG"
case "$1 $2" in
  "pr list")      echo "${STUB_PR_NUMBER:-}" ;;
  "pr create")    if [ -n "${STUB_PR_CREATE_FAIL:-}" ]; then echo "GitHub Actions is not permitted to create or approve pull requests" >&2; exit 1; fi
                  echo "https://github.com/o/r/pull/7" ;;
  "issue list")   echo "${STUB_ISSUE_NUMBER:-}" ;;
  "issue create") echo "https://github.com/o/r/issues/9" ;;
  "workflow run") if [ -n "${STUB_CI_FAIL:-}" ]; then exit 1; fi ;;
esac
exit 0
GHEOF
chmod +x "$WORK/bin/gh"

setup() { # setup CHANGED HAS_SECURITY  -> fresh origin + clone + review output
  rm -rf "$WORK/origin.git" "$WORK/clone" "$WORK/out"
  git init -q --bare "$WORK/origin.git"
  git clone -q "$WORK/origin.git" "$WORK/clone" 2>/dev/null
  ( cd "$WORK/clone" && git config user.email t@t && git config user.name t && git checkout -q -b main \
    && printf '#@ updated 2026-10-24\nphp\t8.4\tfixed\t8.4.27\tC\thttps://example.test/\tn\n' > advisories.tsv \
    && git add advisories.tsv && git commit -q -m init && git push -q origin main 2>/dev/null )
  if [ "$1" = true ]; then printf '#@ updated 2026-11-07\n#@ reviewed php 8.4 8.4.28 2026-11-07\nphp\t8.4\tfixed\t8.4.27\tC\thttps://example.test/\tn\n' > "$WORK/clone/advisories.tsv"; fi
  mkdir -p "$WORK/out"; echo "# body" > "$WORK/out/body.md"
  printf '{"changed": %s, "has_security": %s, "title": "Advisory data review 2026-11-07: 1 to mark reviewed, 0 need a rule"}\n' "$1" "$2" > "$WORK/out/summary.json"
  export GH_LOG="$WORK/gh.log"; : > "$GH_LOG"
  unset STUB_PR_NUMBER STUB_PR_CREATE_FAIL STUB_ISSUE_NUMBER STUB_CI_FAIL
}
run() { ( cd "$WORK/clone" && PATH="$WORK/bin:$PATH" REVIEW_OUT="$WORK/out" GH_REPO=o/r "$BASH" "$SCRIPT" >"$WORK/run.out" 2>&1 ); }
remote_has_branch() { git --git-dir="$WORK/origin.git" rev-parse --verify -q "refs/heads/data-review/auto" >/dev/null; }

setup false false; run; rc=$?
check "nothing to review: exit 0, no gh calls, no branch" bash -c "[ $rc = 0 ] && [ ! -s '$GH_LOG' ]"
check "nothing to review: origin has no bot branch" bash -c "! git --git-dir='$WORK/origin.git' rev-parse --verify -q refs/heads/data-review/auto"

setup true false; run; rc=$?
check "diff: exit 0" [ "$rc" = 0 ]
check "diff: bot branch pushed" remote_has_branch
check "diff: the pushed commit changes only advisories.tsv" bash -c "[ \"\$(git --git-dir='$WORK/origin.git' diff --name-only main data-review/auto)\" = advisories.tsv ]"
check "diff: main on origin is untouched" bash -c "[ \"\$(git --git-dir='$WORK/origin.git' show main:advisories.tsv | grep -c reviewed)\" = 0 ]"
check "diff: CI is started on the branch" logged "workflow run ci.yml --repo o/r --ref data-review/auto"
check "diff: a DRAFT pull request is created" logged "pr create --repo o/r --draft --base main --head data-review/auto"
check "diff: no issue when the PR worked" not_logged "issue create"

setup true false; export STUB_PR_NUMBER=7; run; rc=$?
check "existing PR: it is updated, not duplicated" bash -c "grep -q 'pr edit 7' '$GH_LOG' && ! grep -q 'pr create' '$GH_LOG'"

setup true false; export STUB_PR_CREATE_FAIL=1; run; rc=$?
check "PR refused: exits 0 and falls back to an issue" bash -c "[ $rc = 0 ] && grep -q 'issue create' '$GH_LOG'"
check "PR refused: the issue links the compare page" grep -q "compare/main...data-review/auto" "$WORK/out/issue-body.md"
check "PR refused: the branch is still pushed" remote_has_branch

setup true false; export STUB_PR_CREATE_FAIL=1 STUB_ISSUE_NUMBER=4; run
check "PR refused + open issue: the issue is updated" bash -c "grep -q 'issue edit 4' '$GH_LOG' && ! grep -q 'issue create' '$GH_LOG'"

setup true false; export STUB_CI_FAIL=1; run; rc=$?
check "CI start fails: still opens the PR" bash -c "[ $rc = 0 ] && grep -q 'pr create' '$GH_LOG'"

setup false true; run; rc=$?
check "needs-a-rule only: an issue, no branch, no PR" bash -c "[ $rc = 0 ] && grep -q 'issue create' '$GH_LOG' && ! grep -q 'pr create' '$GH_LOG'"
check "needs-a-rule only: nothing pushed" bash -c "! git --git-dir='$WORK/origin.git' rev-parse --verify -q refs/heads/data-review/auto"

setup false true; export STUB_ISSUE_NUMBER=4; run
check "needs-a-rule only + open issue: it is updated" bash -c "grep -q 'issue edit 4' '$GH_LOG' && ! grep -q 'issue create' '$GH_LOG'"

setup true true; run
check "diff AND needs-a-rule: the PR body is the full body" logged "--body-file $WORK/out/body.md"

setup true false; export TITLE_PREFIX="[DEMO] "; ( cd "$WORK/clone" && PATH="$WORK/bin:$PATH" REVIEW_OUT="$WORK/out" GH_REPO=o/r TITLE_PREFIX="[DEMO] " "$BASH" "$SCRIPT" >/dev/null 2>&1 )
check "title prefix is applied" logged "\[DEMO\] Advisory data review"
unset TITLE_PREFIX

setup true false; rm "$WORK/out/body.md"; run; rc=$?
check "missing input: exit 2" [ "$rc" = 2 ]

echo; echo "passed: $PASS  failed: $FAIL"
[ "$FAIL" = 0 ]
