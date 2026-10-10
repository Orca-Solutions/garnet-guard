# Garnet Guard site

The landing page and, once `docs/rules/` exists, one page per rule.

```sh
uv run site/build.py                 # writes site/_build/
python3 -m http.server -d site/_build 8000
```

- `index.html`, `assets/`: the landing page. Plain HTML and CSS, one small script for the replay tabs, nothing loaded from third parties.
- `replays/2026-10-10.txt`: the verbatim `uv run python -m backtest` output the replay gallery quotes. Replace it, and the page's excerpts, whenever the replays are re-run.
- `assets/brand/`: copies of files from `docs/brand/`. Regenerate them there with `generate.py`, then copy them here.
- `build.py`: renders `docs/rules/GRN-XXXX.md` to `/rules/GRN-XXXX` and `docs/rules/README.md` to `/rules/`. Rule links with no page yet fall back to the landing page.

No domain is decided. The site uses relative links only; pass the domain once with `--base-url` or `GARNET_SITE_URL` when there is one. Hosting (Cloudflare Pages or GitHub Pages, docs/DEVOPS.md) is also open: either serves `site/_build` as it is, with `uv run site/build.py` as the build command.
