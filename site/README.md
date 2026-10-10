# Garnet Guard site

The landing page, one page per rule, and the blog.

```sh
uv run site/build.py                 # writes site/_build/
python3 -m http.server -d site/_build 8000
```

- `index.html`, `assets/`: the landing page, from the brand thread's design. Plain HTML and CSS, one small script for the replay tabs, nothing loaded from third parties (the CSP allows only same-origin files).
- `assets/fonts/`: Inter (variable, with the optical-size axis) and JetBrains Mono, Latin subsets from Fontsource, self-hosted under the SIL Open Font License (licences alongside).
- `assets/brand/`: copies of brand-kit files with the C2PA metadata stripped. The kit in `docs/brand/` is canonical; regenerate there with `generate.py`, then copy.
- `replays/2026-10-10.txt`: the verbatim `uv run python -m backtest` output the replay gallery quotes. Replace it, and the page's excerpts, whenever the replays are re-run.
- `build.py`: renders `docs/rules/GRN-XXXX.md` to `/rules/GRN-XXXX`, `docs/rules/README.md` to `/rules/`, and `blog/YYYY-MM-DD-slug.md` (front matter: `title`, `summary`, optional `draft: true`) to `/blog/YYYY-MM-DD-slug` with a list at `/blog/`. Rule and blog pages reuse the landing page's header and footer. Rule links with no page yet fall back to the landing page.
- The "Try it on your own wheels" section and its nav link ship with `hidden` until the in-browser playground works; remove the attribute on both to show them.

No domain is decided. The site uses relative links only; pass the domain once with `--base-url` or `GARNET_SITE_URL` when there is one, which also adds canonical links and the Atom feed at `/blog/feed.xml`. Either Cloudflare Pages or GitHub Pages serves `site/_build` as it is, with `uv run site/build.py` as the build command.
