#!/usr/bin/env bash
# Renders the downloaded JSON report as the PR comment. The artifact comes from
# a pull_request run, which a fork controls, so only report.json is read and
# the renderer validates it and escapes every string in it.
set -euo pipefail

out="${RUNNER_TEMP:?}/garnet-guard"
mkdir -p "$out"
report="$RUNNER_TEMP/garnet-guard-artifact/report.json"
comment="$out/comment.md"
if [[ ! -f "$report" || -L "$report" ]]; then
  # Couldn't check is never a pass: say so on the pull request.
  run_url="$(jq -r '.workflow_run.html_url // empty' "${GITHUB_EVENT_PATH:?}")"
  [[ "$run_url" =~ ^${GITHUB_SERVER_URL:?}/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/actions/runs/[0-9]+$ ]] || run_url="${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY:?}/actions"
  favicon="https://raw.githubusercontent.com/orca-solutions/garnet-guard/main/docs/brand/favicon/favicon-16.svg"
  {
    echo "<!-- garnet:report -->"
    echo "<img src=\"$favicon\" width=\"16\" height=\"16\" alt=\"\"> **Garnet Guard couldn't check this pull request**"
    echo
    echo "Nothing was checked, so this is not a pass. The [workflow run]($run_url) log says why."
  } > "$comment"
  echo "::error title=Garnet Guard::The pull_request run left no report.json in its artifact."
  echo "comment-path=$comment" >> "${GITHUB_OUTPUT:?}"
  echo "no-changes=false" >> "$GITHUB_OUTPUT"
  exit 0
fi
case "${GARNET_FOOTER:-true}" in true|false) ;; *) echo "::error title=Garnet Guard::footer must be true or false."; exit 1 ;; esac

export UV_PROJECT_ENVIRONMENT="$GARNET_ROOT/.venv"
export UV_PYTHON="${UV_PYTHON:-3.12}"
uv --no-config sync --quiet --frozen --no-dev --project "$GARNET_ROOT"
render=(uv --no-config run --no-sync --frozen --project "$GARNET_ROOT"
        python -m garnet_guard.markdown "$report" --output "$comment")
[[ "${GARNET_FOOTER:-true}" == "false" ]] && render+=(--no-footer)
"${render[@]}"
cat "$comment" >> "${GITHUB_STEP_SUMMARY:-/dev/null}"

echo "comment-path=$comment" >> "${GITHUB_OUTPUT:?}"
if [[ "$(jq '.changes | length' "$report")" == "0" ]]; then
  echo "no-changes=true" >> "$GITHUB_OUTPUT"
else
  echo "no-changes=false" >> "$GITHUB_OUTPUT"
fi
