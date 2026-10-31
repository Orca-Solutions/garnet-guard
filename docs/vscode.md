# Garnet Guard in VS Code

Garnet Guard has no VS Code extension yet. One is planned for after 0.3 ([ROADMAP.md](../ROADMAP.md), [SPEC §10.5](SPEC-v1.md#105-vs-code-extension)): it will run `garnet check` when a lockfile changes and put each finding on the line that pins the new version. Until then, two things work in VS Code with no extension of Garnet's own.

## The Action's comment, in the editor

If you review dependency pull requests in VS Code with the [GitHub Pull Requests](https://github.com/microsoft/vscode-pull-request-github) extension, Garnet's comment is on the pull request like any other comment, and the Action's result is in its checks. Nothing to set up beyond the Action itself ([action.md](action.md)).

## The CLI's findings on the lockfile lines

`garnet check` writes SARIF, the format GitHub code scanning reads, and Microsoft's [SARIF Viewer](https://github.com/microsoft/sarif-vscode-extension) extension (`MS-SarifVSCode.sarif-viewer`) opens a SARIF file in the editor: a results panel, entries in the Problems list, and squiggles in the file each result points at. Garnet's SARIF locates each finding on the lockfile line that pins the new version and carries the rule's explain text and a link to its page, because the Action's code scanning upload needs the same things.

You need:

- the `garnet` command: `uv tool install garnet-guard` or `pipx install garnet-guard`;
- the SARIF Viewer extension, installed from the Marketplace.

Then, in the integrated terminal at the repository root:

```sh
garnet check --git-base main --format sarif --output garnet.sarif
```

This compares every lockfile Garnet reads (uv.lock, poetry.lock, pylock.toml, pinned requirements files) with the same file on `main` and checks each package whose version changed. In a fresh clone the branch may be `origin/main`. Add `garnet.sarif` to `.gitignore`.

Open `garnet.sarif`. The viewer's panel lists each finding with its lockfile, line, severity and message; selecting one opens the lockfile at that line. `block` shows as an error, `warn` as a warning and `info` as a note. Each result's help is the rule's explanation and what to do, with a link to the rule page. The lockfile path in the file is relative to the repository root, which is how the viewer matches it to the open folder; if the squiggles don't appear, the panel still lists every finding with its path and line.

When nothing changed, the file has no results and the panel is empty. That means no changed package; it does not mean the lockfile was checked for anything else.

Once you have reviewed a finding, an ignore in `garnet.toml` silences it until a date you choose ([policy.md](policy.md)); run the command again and it drops out of the file. The same ignore applies in the Action and the CLI.

### As a task

To run it from **Terminal → Run Task** instead of typing it, add to `.vscode/tasks.json`:

```json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "Garnet: check lockfile changes",
      "type": "shell",
      "command": "garnet check --git-base main --format sarif --output garnet.sarif --fail-on warn",
      "problemMatcher": []
    }
  ]
}
```

`--fail-on warn` makes the task end with an error when a finding is at `warn` or above, so VS Code says so; the file is written either way. Then open `garnet.sarif`, or leave it open and the viewer reloads it.

## What this route doesn't do

- It doesn't run on its own when a lockfile changes. You run the command after `uv lock`, `uv add`, a branch switch or a merge.
- Each run downloads the changed packages' files again, so a second look at the same change takes as long as the first. The download cache that will fix this is not built yet (`--cache-dir` says so).
- It is the CLI, so it talks only to PyPI, files.pythonhosted.org, the npm registry, GitHub and OSV, as the CLI always does, and nothing is sent to Orca Solutions ([ADR-0008](decisions/0008-no-telemetry.md)).

The planned extension removes the first two. The third stays.
