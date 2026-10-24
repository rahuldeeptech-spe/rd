#!/usr/bin/env bash
# open_review.sh - turn the output of monitor/propose.py into a draft pull request, or into an issue.
#
# It never merges anything. A person reviews and merges (or closes) what this opens.
#
# Environment:
#   REVIEW_OUT    directory with body.md and summary.json from propose.py (required)
#   REVIEW_FILE   path of the advisories file inside the repository (default advisories.tsv)
#   GH_REPO       owner/name (required)
#   BASE          base branch (default main)
#   BRANCH        bot-owned branch for the proposal (default data-review/auto); it is force-pushed
#   TITLE_PREFIX  optional prefix for titles, e.g. "[DEMO] "
# Needs git, gh and python3; gh needs GH_TOKEN.
#
# Behaviour:
#   * file changed          -> push BRANCH, start CI on it, then create or update ONE draft PR. If GitHub refuses to let
#                              Actions create pull requests, open/update an issue that links the branch instead.
#   * only "needs a rule"   -> open or update ONE issue (there is no diff to put in a PR).
#   * nothing at all        -> do nothing.
set -euo pipefail

: "${REVIEW_OUT:?REVIEW_OUT is required}"
: "${GH_REPO:?GH_REPO is required}"
REVIEW_FILE="${REVIEW_FILE:-advisories.tsv}"
BASE="${BASE:-main}"
BRANCH="${BRANCH:-data-review/auto}"
TITLE_PREFIX="${TITLE_PREFIX:-}"

BODY="$REVIEW_OUT/body.md"
if [ ! -r "$BODY" ] || [ ! -r "$REVIEW_OUT/summary.json" ]; then
  echo "open_review: missing body.md or summary.json in $REVIEW_OUT" >&2
  exit 2
fi

field() { python3 -c 'import json,sys; v=json.load(open(sys.argv[1]))[sys.argv[2]]; print(str(v).lower() if isinstance(v,bool) else v)' "$REVIEW_OUT/summary.json" "$1"; }
CHANGED="$(field changed)"
NEEDS_RULE="$(field has_security)"
TITLE="${TITLE_PREFIX}$(field title)"

if [ "$CHANGED" != true ] && [ "$NEEDS_RULE" != true ]; then
  echo "open_review: nothing to review"
  exit 0
fi

# One rolling issue at a time: update it instead of opening a new one every week.
upsert_issue() { # upsert_issue BODY_FILE
  local existing
  existing="$(gh issue list --repo "$GH_REPO" --state open --search "\"Advisory data review\" in:title" --json number --jq '.[0].number // empty')"
  if [ -n "$existing" ]; then
    gh issue edit "$existing" --repo "$GH_REPO" --title "$TITLE" --body-file "$1"
    echo "open_review: updated issue #$existing"
  else
    gh issue create --repo "$GH_REPO" --title "$TITLE" --body-file "$1"
  fi
}

if [ "$CHANGED" != true ]; then
  upsert_issue "$BODY"
  exit 0
fi

git config user.name "github-actions[bot]"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
git checkout -B "$BRANCH"
git add -- "$REVIEW_FILE"
git commit -q -m "$TITLE" -m "Opened by the weekly data-review workflow. Merging is the reviewer's statement that the release notes were read."
git push --force origin "HEAD:refs/heads/$BRANCH"

# Pushes made with GITHUB_TOKEN do not start workflows, so start CI by hand: the required checks must exist on this commit.
gh workflow run ci.yml --repo "$GH_REPO" --ref "$BRANCH" || echo "open_review: could not start CI on $BRANCH (start it from the Actions tab)" >&2

existing_pr="$(gh pr list --repo "$GH_REPO" --head "$BRANCH" --state open --json number --jq '.[0].number // empty')"
if [ -n "$existing_pr" ]; then
  gh pr edit "$existing_pr" --repo "$GH_REPO" --title "$TITLE" --body-file "$BODY"
  echo "open_review: updated pull request #$existing_pr"
elif gh pr create --repo "$GH_REPO" --draft --base "$BASE" --head "$BRANCH" --title "$TITLE" --body-file "$BODY"; then
  echo "open_review: opened a draft pull request"
else
  # Settings > Actions > General > "Allow GitHub Actions to create and approve pull requests" is off (the default).
  { cat "$BODY"; printf '\n---\nThe change is ready on branch "%s". GitHub would not let this workflow open a pull request, so open it yourself: https://github.com/%s/compare/%s...%s?expand=1\n' \
      "$BRANCH" "$GH_REPO" "$BASE" "$BRANCH"; } > "$REVIEW_OUT/issue-body.md"
  upsert_issue "$REVIEW_OUT/issue-body.md"
fi
