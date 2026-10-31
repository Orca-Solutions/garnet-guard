# Install wrapper

Put `garnet` in front of a pip or uv command, `garnet pip install requests==2.32.3` or `garnet uv add httpx`, and Garnet Guard checks what the command would change before anything is installed, then installs only what it checked.

This is a preview. npm, pnpm, yarn, poetry, `uv pip`, `uv tool` and `uvx` aren't checked yet, and the wrapper doesn't accept them.

## What the wrapper does

```text
garnet pip install <pip install arguments> [--garnet-force]
garnet uv add|remove|lock|sync <uv arguments> [--garnet-force]
```

1. **Read the command without running anything.** Every `-r` and `-c` file is read too, recursively. Garnet refuses, as "can't check", anything that would build a package or that it can't compare with a PyPI release: `--no-binary`, `-e`/`--editable`, local paths and archives, URLs and VCS requirements, uv's `--build`, path, git, URL, editable and workspace sources, `--target`, `--prefix`, `--user` and a few others. pip settings in the environment or pip's configuration that add requirement files (`PIP_REQUIREMENT`, `PIP_CONSTRAINT`, `requirement` in `pip.conf`) are refused the same way. Values from pip's configuration are never printed, because they can hold index credentials, and the credentials in a URL (`https://user:token@host`) are shown as `****` in everything Garnet prints, the command included.
2. **Resolve with builds turned off.**
   - pip: `<python> -I -m pip install --dry-run --quiet --report <tmp> <your arguments> --only-binary :all:`. `--only-binary` comes last, so nothing earlier in the command can turn builds back on.
   - uv: in a private copy of `pyproject.toml`, `uv.lock`, `uv.toml` and `.python-version` (a folder only you can read, never `.venv`): `uv add|remove --no-sync --no-build …` or `uv lock --no-build …`, with `UV_NO_BUILD=1`. For `uv sync`, `uv lock --check --no-build` first, then `uv lock --no-build` only if the lockfile is out of date.
3. **Compare and check.** The base is what you have now: `pip inspect` for pip, and for uv the `uv.lock` committed at git `HEAD` (or the working-tree copy when it isn't tracked). The head is the resolution. Every change is checked like `garnet check` checks it, with the policy `garnet check` would read here (`garnet.toml`, else `[tool.garnet]` in `pyproject.toml`).
4. **Install exactly what was checked, or nothing.**
   - pip runs your command again with `--only-binary :all: -c <checked pins>`. The pins file lists every checked version with its wheel's sha256, so pip can install only those files.
   - uv writes the checked `pyproject.toml` and `uv.lock` back, but only if neither changed while Garnet was checking, then runs `uv sync --frozen` (with `--inexact` after `uv add`, as uv does) and `--no-build-package` for each changed package. `uv lock` and `--no-sync` stop after writing the lockfile.
   - The exit code is the package manager's.

Why builds are off: pip and uv both run a package's build code while resolving a source distribution (pip even with `--dry-run`, uv when an sdist's metadata is dynamic). Garnet never runs code it inspects ([ADR-0005](decisions/0005-never-execute-package-code.md)).

### Outcomes

| What Garnet finds | Wrapper | Exit code |
|---|---|---|
| Nothing at or above `fail_on` | Prints the findings, then installs what was checked | the package manager's |
| Findings at or above `fail_on` (`block` unless the policy says `warn`) | Prints the findings and installs nothing | 2 for block, 1 for warn |
| The command can't be checked: a refusal above, or it can't be resolved without building | Prints what it could check, what needs a build and why, and what you can do; installs nothing | 3 |
| `uv lock --check`, `--check-exists` or `--dry-run` | Runs in the copy and writes nothing | uv's |

`--garnet-force` installs anyway. After block findings it installs what was checked; when the command couldn't be checked it runs your command unchanged and prints a "not checked" line for each package first.

### When a newer release needs a build

With builds off, pip and uv quietly fall back to an older release when the newest one needs a source-only dependency. Garnet compares each package you asked for with the newest release on PyPI that matches your specifier, your Python and your pre-release setting, and tries that release on its own. If the newest needs a build, the install is "can't check" rather than a pass, because running the plain command would install a release Garnet didn't check and run that dependency's build code:

```text
$ garnet pip install num2words
num2words (new) → 0.5.6: WARN
  …

Garnet Guard checked 1 dependency change (above), but not the command as written. Nothing was installed.
  - num2words 0.5.14 needs docopt>=0.6.2, which is published only as source. Resolving docopt would run its build code, so Garnet Guard didn't. Without building, num2words resolves to 0.5.6.

What you can do:
  - Check a version that resolves without building: garnet pip install num2words==0.5.6
  - Run pip install num2words yourself. Garnet Guard doesn't check that, and it may run
    build code from the packages above.
  - Run it unchecked through Garnet Guard: garnet pip install num2words --garnet-force
```

The comparison is skipped when the command limits releases by date or type (`--uploaded-prior-to`, `--only-final`, uv's `--exclude-newer` or a `--resolution` other than `highest`). A fallback in an indirect dependency isn't seen this way; installing exactly what was checked covers it.

## Limits in this preview

- pip: `--user`, `--target`, `--prefix` and `--root` installs, `--group`, and requirements read from scripts are "can't check". `pip inspect` (pip 22.2 or later) is needed for the base.
- uv: single projects only; workspaces and path, git, URL, editable or workspace sources are "can't check". A packaged project whose metadata is dynamic (for example `dynamic = ["version"]`) is "can't check", because uv would run the project's build backend to read it.
- A package installed from an index other than PyPI is reported as GRN-E005, not compared.
