# Garnet Guard GitHub Action

The Action runs `garnet check` on every pull request that changes a lockfile and posts one comment with the result. The comment is designed for Dependabot and Renovate pull requests, but it works on any pull request. It follows SPEC §10.2 and §9.4.

> Status: preview. Until a release is tagged, the examples below carry a `<release-commit-sha>` placeholder. A `policy` input arrives when `garnet check` reads policy files; it will read the policy from the pull request's base commit, so a pull request can't relax its own policy.

## Quick start

Copy [`action/examples/garnet-guard.yml`](../action/examples/garnet-guard.yml) to `.github/workflows/garnet-guard.yml`:

```yaml
name: Garnet Guard
on:
  pull_request:
    paths: ["**/uv.lock", "**/poetry.lock", "**/pylock.toml", "**/pylock.*.toml", "**/requirements*.txt", "garnet.toml"]
permissions: {}
jobs:
  garnet-guard:
    runs-on: ubuntu-latest
    permissions:
      contents: read        # read the lockfiles and the base commit
      pull-requests: write  # post or update the comment
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: orca-solutions/garnet-guard@<release-commit-sha> # v0.1.0
```

Pin the Action to a full commit SHA, as you would any third-party Action. A tag can be moved and a SHA can't.

Dependabot pull requests get a read-only token by default. The `permissions` block above is what lets the job comment on them ([GitHub docs](https://docs.github.com/en/code-security/dependabot/troubleshooting-dependabot/troubleshooting-dependabot-on-github-actions)). Renovate pull requests from branches in the repository work the same way.

## Inputs

| Input | Default | Meaning |
|---|---|---|
| `lockfiles` | `auto` | `auto` checks every lockfile Garnet Guard recognizes. Otherwise, give a newline-separated list of paths relative to the repository root. |
| `comment` | `true` | Post or update one pull request comment. |
| `footer` | `true` | End the comment with one line of links to Garnet Guard's docs. Set it to `false` to remove that line. The footer links only to documentation. |
| `fail-on` | `block` | Fail the step at this verdict or worse: `warn`, `block` or `never`. |
| `github-token` | `${{ github.token }}` | Used to fetch the base commit, look up release tags, and post the comment. |

SARIF upload (`sarif:` in SPEC §10.2) arrives with the SARIF reporter.

## Outputs

| Output | Meaning |
|---|---|
| `verdict` | `pass`, `warn` or `block`. It is empty when Garnet Guard couldn't produce a report. |
| `report-path` | The JSON report (SPEC §9.2). |
| `comment-path` | The rendered comment (Markdown). |

## What it does

1. It refuses any event other than `pull_request`. Under `pull_request_target`, it stops with an error and changes nothing.
2. It fetches the base commit if the checkout doesn't have it.
3. It refuses lockfiles that are symbolic links, since one could point at a file on the runner.
4. It runs `garnet check --git-base <base-sha>` from the Action's own locked environment (`uv sync --frozen`). uv's configuration discovery is turned off (`--no-config`), so a `uv.toml` or `[tool.uv]` table in the pull request can't change how Garnet Guard is installed. Python runs with `PYTHONSAFEPATH=1` and the renderer with `-I`, so a module in the pull request can't shadow Garnet Guard's.
5. It renders the comment from the JSON report and adds it to the job summary.
6. It posts the comment, or updates the earlier one. The earlier comment is found by its `<!-- garnet:report -->` marker and its author (`github-actions[bot]`), so a comment someone else wrote with the same marker is never edited. A pull request with no dependency changes gets no new comment, but an earlier comment is updated.
7. It fails the step according to `fail-on`.

If Garnet Guard itself fails, or a report is missing or invalid, the comment says it **couldn't check** the pull request and links to the run log, and the step fails (exit code 3). A failure is never reported as a pass.

## Pull requests from forks

Pull requests from forks get a read-only token, so the single workflow can't comment on them. It still writes the report to the job summary. To comment on forks too, use the two-workflow pattern:

- [`action/examples/garnet-guard-fork.yml`](../action/examples/garnet-guard-fork.yml) runs on `pull_request` with a read-only token, sets `comment: false`, and uploads the JSON report as the `garnet-guard-report` artifact.
- [`action/examples/garnet-guard-comment.yml`](../action/examples/garnet-guard-comment.yml) runs on `workflow_run` after the check finishes and uses `orca-solutions/garnet-guard/action/comment`.

The comment job never checks out or runs pull request code. It treats the artifact as untrusted, because a fork controls the workflow that produced it:

- It reads only `report.json` and ignores anything else in the artifact.
- It renders the comment itself, so it never posts Markdown from the artifact. The renderer validates rule IDs and verdicts and escapes every string, so the report can't add links, mentions or HTML.
- It finds the pull request from the `workflow_run` event, by head repository and branch, and requires the pull request's head commit to be the commit that was checked. A stale run therefore posts nothing.

A fork's own workflow decides what its report says, so comments on fork pull requests end with a line saying the report came from the pull request's own workflow run. Treat such a comment as information from that fork, not as an independent check.

The same holds for any pull request that edits the workflow file itself, for example to set `fail-on: never`: the `pull_request` event runs the pull request's version of the workflow. Review workflow changes in dependency pull requests like any other code.

## Permissions

| Job | Permissions |
|---|---|
| Single workflow | `contents: read`, `pull-requests: write` |
| Fork pattern, check job | `contents: read` |
| Fork pattern, comment job | `actions: read`, `pull-requests: write` |

Tokens are never printed. The token is passed to `garnet` by environment variable name (`--github-token-env`), and the git authorization header is masked in the log.

## Runner requirements

The runner needs `bash`, `git`, `jq` and `gh`. GitHub-hosted runners have all four. The Action installs uv with `astral-sh/setup-uv`, pinned by SHA, and runs on Python 3.12 unless `UV_PYTHON` is set.
