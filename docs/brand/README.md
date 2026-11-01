# Brand copies

The Garnet Guard brand kit and website live in the private `orca-solutions/gg-landing` repository, under `brand/`. This folder keeps copies of only the files this repository needs, so they work for everyone who reads it:

| File | Used by |
|---|---|
| `brand-kit.md` | The voice rules that AGENTS.md, CONTRIBUTING.md and PRINCIPLES.md point to |
| `lockup/lockup-horizontal.svg`, `lockup/lockup-horizontal-reverse.svg` | The README header, light and dark |
| `pr-comment/pr-comment-light.svg`, `pr-comment/pr-comment-dark.svg` | The README's sample PR comment |
| `badge/checked-by-garnet-guard.svg` | The README badge, once Garnet Guard checks its own dependency PRs |
| `favicon/favicon-16.svg` | The icon in the Action's PR comment (`action/run.sh`, `action/comment/render.sh`, `src/garnet_guard/markdown.py`) |

Don't edit these files here. Change the kit in gg-landing, regenerate it there, and copy the changed files over the ones here. These copies match gg-landing at commit 534c5a4.
