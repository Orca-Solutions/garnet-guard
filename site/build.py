# /// script
# requires-python = ">=3.11"
# dependencies = ["markdown-it-py>=3,<5", "pyyaml>=6,<7"]
# ///
"""Build the static site into site/_build.

    uv run site/build.py

Copies the landing page and its assets, and renders each rule page from
docs/rules/GRN-XXXX.md (YAML front matter plus Markdown) to /rules/GRN-XXXX,
with docs/rules/README.md as /rules/. The output is plain files that Cloudflare
Pages or GitHub Pages serve as they are; both map /rules/GRN-T001 to
rules/GRN-T001.html.

The public domain is not decided, so nothing hardcodes one. Pass it once with
--base-url (or GARNET_SITE_URL) to add canonical and og:url links; without it
the site uses relative links only.

Rule IDs linked from the landing page that have no page yet fall back to the
landing page's own `garnet explain` excerpt, or to the rule list, with a
warning. Nothing here is package-supplied text, but raw HTML in the Markdown
is still disabled.
"""

from __future__ import annotations

import argparse
import html
import os
import re
import shutil
import sys
from pathlib import Path

import yaml
from markdown_it import MarkdownIt

SITE = Path(__file__).resolve().parent
REPO = SITE.parent
STATIC = ("index.html", "assets", "replays")
RULE_ID = re.compile(r"GRN-[A-Z]\d{3}")
FRONT_MATTER = re.compile(r"\A---\n(.*?)\n---\n", re.DOTALL)

PAGE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="Content-Security-Policy" content="default-src 'self'; img-src 'self'; style-src 'self'; script-src 'self'; base-uri 'none'; form-action 'none'">
  <meta name="referrer" content="no-referrer">
  <title>{title} · Garnet Guard</title>
  <meta name="description" content="{description}">
  <link rel="icon" type="image/svg+xml" href="{root}assets/brand/favicon-32.svg">
  <link rel="stylesheet" href="{root}assets/style.css">
<!-- canonical -->
</head>
<body>
  <header class="top">
    <div class="wrap top-inner">
      <a class="brand" href="{root}" aria-label="Garnet Guard home">
        <img class="lockup lockup-light" src="{root}assets/brand/lockup-horizontal.svg" alt="Garnet Guard" width="178" height="40">
        <img class="lockup lockup-dark" src="{root}assets/brand/lockup-horizontal-reverse.svg" alt="" width="178" height="40">
      </a>
      <nav aria-label="Primary">
        <a href="{root}#replays">Replays</a>
        <a href="{root}rules/">Rules</a>
        <a href="https://github.com/orca-solutions/garnet-guard">GitHub</a>
      </nav>
    </div>
  </header>
  <main class="doc">
    <div class="wrap">
      <p class="crumbs">{crumbs}</p>
{meta}{body}
    </div>
  </main>
</body>
</html>
"""


def split_front_matter(text: str) -> tuple[dict[str, object], str]:
    m = FRONT_MATTER.match(text)
    if not m:
        return {}, text
    data = yaml.safe_load(m.group(1)) or {}
    if not isinstance(data, dict):
        raise SystemExit("front matter must be a YAML mapping")
    return data, text[m.end() :]


def rewrite_md_links(rendered: str) -> str:
    """Point links between rule docs at their published URLs."""
    rendered = re.sub(
        r'href="(?:\./)?(GRN-[A-Z]\d{3})\.md(#[^"]*)?"', r'href="\1\2"', rendered
    )
    return re.sub(r'href="(?:\./)?README\.md(#[^"]*)?"', r'href="./\1"', rendered)


def render_rules(rules_dir: Path, out: Path, md: MarkdownIt) -> set[str]:
    built: set[str] = set()
    if not rules_dir.is_dir():
        print(f"note: {rules_dir} does not exist; no rule pages built", file=sys.stderr)
        return built
    (out / "rules").mkdir(parents=True, exist_ok=True)
    for src in sorted(rules_dir.glob("GRN-*.md")):
        meta, body = split_front_matter(src.read_text(encoding="utf-8"))
        rule_id = str(meta.get("id", src.stem))
        if rule_id != src.stem or not RULE_ID.fullmatch(rule_id):
            raise SystemExit(
                f"{src}: front matter id {rule_id!r} doesn't match the file name"
            )
        name = str(meta.get("name", ""))
        chips = [
            str(meta[k])
            for k in ("kind", "default_severity", "status")
            if meta.get(k) is not None
        ]
        meta_html = (
            '      <p class="rule-meta">'
            + "".join(f"<span>{html.escape(c)}</span>" for c in chips)
            + "</p>\n"
            if chips
            else ""
        )
        page = PAGE.format(
            title=html.escape(f"{rule_id} {name}".strip()),
            description=html.escape(
                f"What Garnet Guard rule {rule_id} means and what to do."
            ),
            root="../",
            crumbs='<a href="./">Rules</a> / ' + html.escape(rule_id),
            meta=meta_html,
            body=rewrite_md_links(md.render(body)),
        )
        (out / "rules" / f"{rule_id}.html").write_text(page, encoding="utf-8")
        built.add(rule_id)
    index = rules_dir / "README.md"
    if index.is_file():
        _, body = split_front_matter(index.read_text(encoding="utf-8"))
        page = PAGE.format(
            title="Rules",
            description="Every rule Garnet Guard checks, what it means and what to do.",
            root="../",
            crumbs='<a href="../">Garnet Guard</a> / Rules',
            meta="",
            body=rewrite_md_links(md.render(body)),
        )
        (out / "rules" / "index.html").write_text(page, encoding="utf-8")
    return built


def fix_landing_rule_links(out: Path, built: set[str], has_index: bool) -> list[str]:
    path = out / "index.html"
    text = path.read_text(encoding="utf-8")
    missing: list[str] = []

    def repl(m: re.Match[str]) -> str:
        rule_id = m.group(1)
        if rule_id in built:
            return m.group(0)
        missing.append(rule_id)
        if f'id="rule-{rule_id}"' in text:
            return f'href="#rule-{rule_id}"'
        return 'href="rules/"' if has_index else 'href="#how"'

    path.write_text(
        re.sub(r'href="rules/(GRN-[A-Z]\d{3})"', repl, text), encoding="utf-8"
    )
    return sorted(set(missing))


def add_canonical(page: Path, url: str) -> None:
    """Fill the <!-- canonical --> slot (rule pages) or add it before </head>."""
    tags = f'  <link rel="canonical" href="{html.escape(url)}">\n  <meta property="og:url" content="{html.escape(url)}">'
    text = page.read_text(encoding="utf-8")
    if "<!-- canonical -->" in text:
        text = text.replace("<!-- canonical -->", tags, 1)
    else:
        text = text.replace("</head>", tags + "\n</head>", 1)
    page.write_text(text, encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--rules", type=Path, default=REPO / "docs" / "rules")
    ap.add_argument("--out", type=Path, default=SITE / "_build")
    ap.add_argument(
        "--base-url",
        default=os.environ.get("GARNET_SITE_URL", ""),
        help="e.g. https://example.org/ (no domain is decided yet)",
    )
    args = ap.parse_args()

    out: Path = args.out
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    for name in STATIC:
        src = SITE / name
        if src.is_dir():
            shutil.copytree(src, out / name)
        else:
            shutil.copy2(src, out / name)

    md = MarkdownIt("commonmark", {"html": False}).enable("table")
    built = render_rules(args.rules, out, md)
    missing = fix_landing_rule_links(
        out, built, (out / "rules" / "index.html").is_file()
    )
    base = args.base_url.rstrip("/")
    for page in out.rglob("*.html"):
        rel = page.relative_to(out).as_posix()
        if base:
            path = (
                ""
                if rel == "index.html"
                else rel.removesuffix("index.html").removesuffix(".html")
            )
            add_canonical(page, f"{base}/{path}")
        else:
            page.write_text(
                page.read_text(encoding="utf-8").replace("<!-- canonical -->\n", ""),
                encoding="utf-8",
            )
    if missing:
        print(
            f"warning: no rule page yet for {', '.join(missing)}; linked to the landing page instead",
            file=sys.stderr,
        )
    print(f"built {out} ({len(built)} rule pages)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
