#!/usr/bin/env bash
# Finds the open pull request a workflow_run event belongs to. Fork runs carry
# no pull_requests list, so look the pull request up by head repository owner
# and branch, then require its head commit to be the commit that was checked.
# Writes the step output "number", or leaves it empty and explains why.
set -euo pipefail

if [[ "${GITHUB_EVENT_NAME:-}" != "workflow_run" ]]; then
  echo "::error title=Garnet Guard::The comment action runs on workflow_run events."
  exit 1
fi
event="${GITHUB_EVENT_PATH:?}"
if [[ "$(jq -r '.workflow_run.event' "$event")" != "pull_request" ]]; then
  echo "The triggering run wasn't for a pull request; nothing to comment on."
  exit 0
fi

sha="$(jq -r '.workflow_run.head_sha // empty' "$event")"
query="$(jq -r '"\(.workflow_run.head_repository.owner.login):\(.workflow_run.head_branch)" | @uri' "$event")"
[[ "$sha" =~ ^[0-9a-f]{40}([0-9a-f]{24})?$ ]] || { echo "::error title=Garnet Guard::The event has no head commit."; exit 1; }

numbers="$(
  gh api "repos/${GITHUB_REPOSITORY:?}/pulls?state=open&per_page=100&head=$query" \
    --jq ".[] | select(.head.sha == \"$sha\") | .number"
)"
number="${numbers%%$'\n'*}"
if [[ ! "$number" =~ ^[0-9]+$ ]]; then
  echo "No open pull request has head commit $sha (it may have been updated or closed since); nothing to comment on."
  exit 0
fi
echo "number=$number" >> "${GITHUB_OUTPUT:?}"
echo "Commenting on #$number."
