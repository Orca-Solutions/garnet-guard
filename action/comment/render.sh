#!/usr/bin/env bash
# Renders the downloaded JSON report as the PR comment. The artifact comes from
# a pull_request run, which a fork controls, so only report.json is read and
# the renderer validates it and escapes every string in it.
set -euo pipefail

out="${RUNNER_TEMP:?}/garnet-guard"
mkdir -p "$out"
report="$RUNNER_TEMP/garnet-guard-artifact/report.json"
comment="$out/comment.md"
couldnt_check() {
  # Couldn't check is never a pass: say so on the pull request, replacing any
  # earlier comment.
  run_url="$(jq -r '.workflow_run.html_url // empty' "${GITHUB_EVENT_PATH:?}")"
  [[ "$run_url" =~ ^${GITHUB_SERVER_URL:?}/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/actions/runs/[0-9]+$ ]] || run_url="${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY:?}/actions"
  favicon="https://raw.githubusercontent.com/orca-solutions/garnet-guard/main/docs/brand/favicon/favicon-16.svg"
  {
    echo "<!-- garnet:report -->"
    echo "<img src=\"$favicon\" width=\"16\" height=\"16\" alt=\"\"> **Garnet Guard couldn't check this pull request**"
    echo
    echo "Nothing was checked, so this is not a pass. The [workflow run]($run_url) log says why."
  } > "$comment"
  echo "::error title=Garnet Guard::$1"
  echo "comment-path=$comment" >> "${GITHUB_OUTPUT:?}"
  echo "no-changes=false" >> "$GITHUB_OUTPUT"
  exit 0
}

rm -f "$comment"
if [[ ! -f "$report" || -L "$report" ]]; then
  couldnt_check "The pull_request run left no report.json in its artifact."
fi
case "${GARNET_FOOTER:-true}" in true|false) ;; *) echo "::error title=Garnet Guard::footer must be true or false."; exit 1 ;; esac

export UV_PROJECT_ENVIRONMENT="$GARNET_ROOT/.venv"
export UV_PYTHON="${UV_PYTHON:-3.12}"
export PYTHONSAFEPATH=1
uv --no-config sync --quiet --frozen --no-dev --project "$GARNET_ROOT" \
  || couldnt_check "Couldn't install Garnet Guard's locked environment."
render=(uv --no-config run --no-sync --frozen --project "$GARNET_ROOT"
        python -I -m garnet_guard.markdown "$report" --output "$comment")
[[ "${GARNET_FOOTER:-true}" == "false" ]] && render+=(--no-footer)
(cd "$out" && "${render[@]}") || couldnt_check "The report in the artifact isn't a valid Garnet Guard report."
changes="$(jq '.changes | length' "$report")" || couldnt_check "The report in the artifact isn't valid JSON."

# A fork's own workflow produced this report; say so on the comment.
head_repo="$(jq -r '.workflow_run.head_repository.full_name // empty' "$GITHUB_EVENT_PATH")"
if [[ "$head_repo" != "${GITHUB_REPOSITORY:?}" ]]; then
  printf '\n<sub>This report came from the pull request'"'"'s own workflow run, which its fork controls.</sub>\n' >> "$comment"
fi
cat "$comment" >> "${GITHUB_STEP_SUMMARY:-/dev/null}"

echo "comment-path=$comment" >> "${GITHUB_OUTPUT:?}"
if [[ "$changes" == "0" ]]; then
  echo "no-changes=true" >> "$GITHUB_OUTPUT"
else
  echo "no-changes=false" >> "$GITHUB_OUTPUT"
fi
