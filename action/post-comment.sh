#!/usr/bin/env bash
# Posts the Garnet Guard comment on a pull request, or updates the one already
# there. The comment is found by its marker and by its author, so a comment
# someone else wrote with the same marker is never edited.
#
# Environment: GARNET_COMMENT (Markdown file), GARNET_PR (number), GH_TOKEN,
# GARNET_UPDATE_ONLY ("true": only update an existing comment, never post a
# new one), GARNET_COMMENT_AUTHOR (default github-actions[bot]).
set -euo pipefail

file="${GARNET_COMMENT:?}"
pr="${GARNET_PR:-}"
repo="${GITHUB_REPOSITORY:?}"
author="${GARNET_COMMENT_AUTHOR:-github-actions[bot]}"
marker="<!-- garnet:report -->"

[[ "$author" =~ ^[A-Za-z0-9-]+(\[bot\])?$ ]] || { echo "::error title=Garnet Guard::GARNET_COMMENT_AUTHOR isn't a GitHub login."; exit 1; }
[[ "$pr" =~ ^[0-9]+$ ]] || { echo "::error title=Garnet Guard::No pull request number to comment on."; exit 1; }
[[ "$(head -n1 "$file")" == "$marker" ]] || { echo "::error title=Garnet Guard::The comment file has no Garnet Guard marker."; exit 1; }
if (( $(wc -m < "$file") > 65536 )); then
  echo "::error title=Garnet Guard::The comment is over GitHub's 65,536-character limit."
  exit 1
fi

warn_no_write() {
  echo "::warning title=Garnet Guard::Couldn't post the pull request comment: $1." \
    "The report is in the job summary. The token needs pull-requests: write;" \
    "for pull requests from forks, use the workflow_run comment job (docs/action.md)."
  exit 0
}

ids="$(
  gh api --paginate "repos/$repo/issues/$pr/comments?per_page=100" \
    --jq ".[] | select(.user.login == \"$author\" and (.body | startswith(\"$marker\"))) | .id"
)" || warn_no_write "couldn't list the existing comments"
existing="${ids%%$'\n'*}"

payload="$(jq -n --rawfile body "$file" '{body: $body}')"
if [[ -n "$existing" ]]; then
  gh api --method PATCH "repos/$repo/issues/comments/$existing" --input - <<< "$payload" > /dev/null \
    || warn_no_write "the update was refused"
  echo "Updated the Garnet Guard comment on #$pr."
elif [[ "${GARNET_UPDATE_ONLY:-false}" == "true" ]]; then
  echo "No dependency changes and no earlier comment, so no comment was posted."
else
  gh api --method POST "repos/$repo/issues/$pr/comments" --input - <<< "$payload" > /dev/null \
    || warn_no_write "the new comment was refused"
  echo "Posted the Garnet Guard comment on #$pr."
fi
