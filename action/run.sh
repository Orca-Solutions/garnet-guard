#!/usr/bin/env bash
# Runs garnet check for the Garnet Guard Action and renders the PR comment.
#
# Inputs arrive as GARNET_* environment variables (see action.yml). This script
# never runs code from the pull request: it reads lockfiles and the policy as
# data, reads the policy from the base commit, and runs Garnet Guard from the
# Action's own directory with uv configuration discovery turned off.
#
# Writes these step outputs: verdict, exit-code, report-path, comment-path,
# pr-number, no-changes. exit-code is garnet's (0, 1 or 2), or 3 when Garnet
# Guard couldn't check the pull request. The script itself exits 0 once it
# knows which pull request it is on, so the comment step can still run.
set -euo pipefail

out="${RUNNER_TEMP:?}/garnet-guard"
mkdir -p "$out"
report="$out/report.json"
comment="$out/comment.md"
ws="${GITHUB_WORKSPACE:?}"
run_url="${GITHUB_SERVER_URL:?}/${GITHUB_REPOSITORY:?}/actions/runs/${GITHUB_RUN_ID:?}"
favicon="https://raw.githubusercontent.com/orca-solutions/garnet-guard/main/docs/brand/favicon/favicon-16.svg"
pr=""

output() { printf '%s=%s\n' "$1" "$2" >> "${GITHUB_OUTPUT:?}"; }

# Stop before any pull request is known: no comment, the step fails.
die() {
  echo "::error title=Garnet Guard::$1"
  output exit-code 3
  exit 3
}

# Stop after the pull request is known: say so in the comment. Couldn't check
# is never a pass (AGENTS.md rule 4).
couldnt_check() {
  echo "::error title=Garnet Guard::$1"
  {
    echo "<!-- garnet:report -->"
    echo "<img src=\"$favicon\" width=\"16\" height=\"16\" alt=\"\"> **Garnet Guard couldn't check this pull request**"
    echo
    echo "Nothing was checked, so this is not a pass. The [workflow run]($run_url) log says why."
  } > "$comment"
  cat "$comment" >> "${GITHUB_STEP_SUMMARY:-/dev/null}"
  output exit-code 3
  output comment-path "$comment"
  output pr-number "$pr"
  output no-changes false
  exit 0
}

# --- Validate the event and inputs ----------------------------------------

case "${GITHUB_EVENT_NAME:-}" in
  pull_request) ;;
  pull_request_target)
    die "Garnet Guard doesn't run on pull_request_target. Use pull_request; for forks, add the workflow_run comment job (docs/action.md)." ;;
  *)
    die "Garnet Guard runs on pull_request events, not ${GITHUB_EVENT_NAME:-unknown}." ;;
esac

event="${GITHUB_EVENT_PATH:?}"
pr="$(jq -r '.pull_request.number // empty' "$event")"
base="$(jq -r '.pull_request.base.sha // empty' "$event")"
[[ "$pr" =~ ^[0-9]+$ ]] || die "The event has no pull request number."
[[ "$base" =~ ^[0-9a-f]{40}([0-9a-f]{24})?$ ]] || die "The event has no base commit."

fail_on="${GARNET_FAIL_ON:-block}"
case "$fail_on" in warn|block|never) ;; *) die "fail-on must be warn, block or never, not '$fail_on'." ;; esac
case "${GARNET_FOOTER:-true}" in true|false) ;; *) die "footer must be true or false." ;; esac

# A repository-relative path with no '..' segments and no leading '/' or '-'.
safe_path() {
  [[ -n "$1" && "$1" != /* && "$1" != -* && "/$1/" != */../* && "$1" != *$'\n'* ]]
}

git -C "$ws" rev-parse --is-inside-work-tree > /dev/null 2>&1 \
  || die "No git checkout in $ws. Add actions/checkout before Garnet Guard."

# --- Fetch the base commit -------------------------------------------------

if ! git -C "$ws" cat-file -e "$base^{commit}" 2> /dev/null; then
  if ! git -C "$ws" fetch --quiet --no-tags --depth=1 origin "$base" 2> /dev/null; then
    # The checkout may not have kept credentials (persist-credentials: false).
    auth="$(printf 'x-access-token:%s' "${GARNET_GITHUB_TOKEN:?}" | base64 -w0)"
    echo "::add-mask::$auth"
    git -C "$ws" -c "http.${GITHUB_SERVER_URL}/.extraheader=AUTHORIZATION: basic $auth" \
      fetch --quiet --no-tags --depth=1 origin "$base" \
      || couldnt_check "Couldn't fetch the base commit $base."
  fi
fi

# --- Policy, read from the base commit -------------------------------------

policy="$out/policy.toml"
policy_path="${GARNET_POLICY:-garnet.toml}"
safe_path "$policy_path" || couldnt_check "policy must be a path inside the repository."
if git -C "$ws" cat-file -e "$base:$policy_path" 2> /dev/null; then
  git -C "$ws" show "$base:$policy_path" > "$policy"
  echo "Using the policy $policy_path from the base commit."
else
  # Pass an explicit default policy so garnet doesn't pick up one the pull
  # request adds.
  printf '[garnet]\nversion = 1\n' > "$policy"
  echo "The base commit has no $policy_path; using the default policy."
fi
if ! git -C "$ws" diff --quiet "$base" -- "$policy_path" 2> /dev/null; then
  echo "::notice title=Garnet Guard::This pull request changes $policy_path. The check uses the base commit's version."
fi

# --- Run garnet check ------------------------------------------------------

args=(check --git-base "$base" --policy "$policy" --format json --output "$report"
      --fail-on "$fail_on" --github-token-env GARNET_GITHUB_TOKEN)
if [[ "${GARNET_LOCKFILES:-auto}" != "auto" ]]; then
  while IFS= read -r line; do
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    [[ -z "$line" ]] && continue
    safe_path "$line" || couldnt_check "lockfiles must be paths inside the repository."
    args+=(--head "$line")
  done <<< "$GARNET_LOCKFILES"
fi

# Garnet runs from the Action's own locked environment. --no-config stops uv
# reading uv.toml or [tool.uv] from the pull request's checkout.
export UV_PROJECT_ENVIRONMENT="$GARNET_ACTION_PATH/.venv"
export UV_PYTHON="${UV_PYTHON:-3.12}"
uvx=(uv --no-config)
"${uvx[@]}" sync --quiet --frozen --no-dev --project "$GARNET_ACTION_PATH" \
  || couldnt_check "Couldn't install Garnet Guard's locked environment."
garnet=("${uvx[@]}" run --no-sync --frozen --project "$GARNET_ACTION_PATH")

set +e
(cd "$ws" && "${garnet[@]}" garnet "${args[@]}")
code=$?
set -e
case "$code" in
  0|1|2) ;;
  *) couldnt_check "garnet check exited with code $code." ;;
esac
[[ -s "$report" ]] || couldnt_check "garnet check wrote no report."

verdict="$(jq -r '.verdict // empty' "$report")"
case "$verdict" in pass|warn|block) ;; *) couldnt_check "The report has no verdict." ;; esac
changes="$(jq '.changes | length' "$report")"

render=("${garnet[@]}" python -m garnet_guard.markdown "$report" --output "$comment")
[[ "${GARNET_FOOTER:-true}" == "false" ]] && render+=(--no-footer)
"${render[@]}" || couldnt_check "Couldn't render the comment."
cat "$comment" >> "${GITHUB_STEP_SUMMARY:-/dev/null}"

output verdict "$verdict"
output exit-code "$code"
output report-path "$report"
output comment-path "$comment"
output pr-number "$pr"
if [[ "$changes" == "0" ]]; then output no-changes true; else output no-changes false; fi
