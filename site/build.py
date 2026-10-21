# /// script
# requires-python = ">=3.11"
# dependencies = ["markdown-it-py>=3,<5", "pyyaml>=6,<7"]
# ///
"""Build the static site into site/_build.

    uv run site/build.py

Copies the landing page and its assets, then renders:

- each rule page from docs/rules/GRN-XXXX.md (YAML front matter plus Markdown)
  to /rules/GRN-XXXX, with docs/rules/README.md as /rules/;
- each post from blog/YYYY-MM-DD-slug.md (front matter: title, date, summary)
  to /blog/YYYY-MM-DD-slug, a list page at /blog/, and an Atom feed at
  /blog/feed.xml when a base URL is set.

Rule and blog pages reuse the landing page's header and footer, so the site has
one source for its chrome. The output is plain files that Cloudflare Pages or
GitHub Pages serve as they are; both map /rules/GRN-T001 to rules/GRN-T001.html.

The public domain is not decided, so nothing hardcodes one. Pass it once with
--base-url (or GARNET_SITE_URL) to add canonical links and the feed; without it
the site uses relative links only.

Rule IDs linked from the landing page that have no page yet fall back to the
landing page's own `garnet explain` excerpt, with a warning. Nothing here is
package-supplied text, but raw HTML in the Markdown is still disabled.
"""

from __future__ import annotations

import argparse
import datetime as dt
import html
import os
import re
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path

import yaml
from markdown_it import MarkdownIt

SITE = Path(__file__).resolve().parent
REPO = SITE.parent
STATIC = ("index.html", "assets", "replays", "_headers")
REPO_DOCS = "https://github.com/orca-solutions/garnet-guard/blob/main/docs/"
RULE_ID = re.compile(r"GRN-[A-Z]\d{3}")
POST_NAME = re.compile(r"(\d{4}-\d{2}-\d{2})-[a-z0-9]+(?:-[a-z0-9]+)*")
FRONT_MATTER = re.compile(r"\A---\n(.*?)\n---\n", re.DOTALL)
CSP = (
    "default-src 'self'; img-src 'self'; style-src 'self'; font-src 'self'; "
    "script-src 'self'; base-uri 'none'; form-action 'none'"
)

PAGE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="Content-Security-Policy" content="{csp}">
  <meta name="referrer" content="no-referrer">
  <title>{title} · Garnet Guard</title>
  <meta name="description" content="{description}">
  <link rel="icon" type="image/svg+xml" href="../assets/brand/favicon-32.svg">
  <link rel="stylesheet" href="../assets/style.css">
{extra_head}</head>
<body>
{header}
<main class="doc">
  <div class="wrap">
    <p class="crumbs">{crumbs}</p>
{meta}{body}
  </div>
</main>
{footer}
</body>
</html>
"""


@dataclass(frozen=True)
class Post:
    slug: str
    title: str
    date: dt.date
    summary: str
    html: str


def split_front_matter(text: str, src: Path) -> tuple[dict[str, object], str]:
    m = FRONT_MATTER.match(text)
    if not m:
        return {}, text
    data = yaml.safe_load(m.group(1)) or {}
    if not isinstance(data, dict):
        raise SystemExit(f"{src}: front matter must be a YAML mapping")
    return data, text[m.end() :]


def chrome(index_html: str) -> tuple[str, str]:
    """The landing page's header and footer, with links made to work one level down."""

    def section(tag: str) -> str:
        m = re.search(rf'<{tag} class="(?:top|foot)">.*?</{tag}>', index_html, re.DOTALL)
        if not m:
            raise SystemExit(f"index.html has no <{tag}> to reuse")
        return m.group(0)

    def relink(m: re.Match[str]) -> str:
        href = m.group(1)
        if re.match(r"[a-z]+:", href):
            return m.group(0)
        if href.startswith("#"):
            return f'href="../{href}"'
        return f'href="../{href.removeprefix("./")}"'

    header = re.sub(r'href="([^"]*)"', relink, section("header"))
    # Sections that only exist on the landing page can't be hidden from here.
    header = re.sub(r'<a href="\.\./#tryit"[^>]*hidden>.*?</a>\s*', "", header, flags=re.DOTALL)
    return header, re.sub(r'href="([^"]*)"', relink, section("footer"))


def rewrite_md_links(rendered: str) -> str:
    """Point links between rule docs at their published URLs, and other repo docs at GitHub."""
    rendered = re.sub(r'href="(?:\./)?(GRN-[A-Z]\d{3})\.md(#[^"]*)?"', r'href="\1\2"', rendered)
    rendered = re.sub(r'href="(?:\./)?README\.md(#[^"]*)?"', r'href="./\1"', rendered)
    return re.sub(
        r'href="\.\./([A-Za-z0-9_./-]+\.md)(#[^"]*)?"', rf'href="{REPO_DOCS}\1\2"', rendered
    )


def page(
    shell: tuple[str, str],
    *,
    title: str,
    description: str,
    crumbs: str,
    body: str,
    meta: str = "",
    extra_head: str = "",
) -> str:
    return PAGE.format(
        csp=CSP,
        title=html.escape(title),
        description=html.escape(description),
        extra_head=extra_head,
        header=shell[0],
        footer=shell[1],
        crumbs=crumbs,
        meta=meta,
        body=body,
    )


def render_rules(
    rules_dir: Path, out: Path, md: MarkdownIt, shell: tuple[str, str]
) -> tuple[set[str], bool]:
    built: set[str] = set()
    if not rules_dir.is_dir():
        print(f"note: {rules_dir} does not exist; no rule pages built", file=sys.stderr)
        return built, False
    (out / "rules").mkdir(parents=True, exist_ok=True)
    for src in sorted(rules_dir.glob("GRN-*.md")):
        meta, body = split_front_matter(src.read_text(encoding="utf-8"), src)
        rule_id = str(meta.get("id", src.stem))
        if rule_id != src.stem or not RULE_ID.fullmatch(rule_id):
            raise SystemExit(f"{src}: front matter id {rule_id!r} doesn't match the file name")
        chips = [
            str(meta[k]) for k in ("kind", "default_severity", "status") if meta.get(k) is not None
        ]
        meta_html = (
            '    <p class="rule-meta">'
            + "".join(f"<span>{html.escape(c)}</span>" for c in chips)
            + "</p>\n"
            if chips
            else ""
        )
        text = page(
            shell,
            title=f"{rule_id} {meta.get('name', '')}".strip(),
            description=f"What Garnet Guard rule {rule_id} means and what to do.",
            crumbs='<a href="./">Rules</a> / ' + html.escape(rule_id),
            meta=meta_html,
            body=rewrite_md_links(md.render(body)),
        )
        (out / "rules" / f"{rule_id}.html").write_text(text, encoding="utf-8")
        built.add(rule_id)
    index = rules_dir / "README.md"
    if not index.is_file():
        return built, False
    _, body = split_front_matter(index.read_text(encoding="utf-8"), index)
    text = page(
        shell,
        title="Rules",
        description="Every rule Garnet Guard checks, what it means and what to do.",
        crumbs='<a href="../">Garnet Guard</a> / Rules',
        body=rewrite_md_links(md.render(body)),
    )
    (out / "rules" / "index.html").write_text(text, encoding="utf-8")
    return built, True


def load_posts(blog_dir: Path, md: MarkdownIt) -> list[Post]:
    posts: list[Post] = []
    if not blog_dir.is_dir():
        return posts
    for src in sorted(blog_dir.glob("*.md")):
        if src.name == "README.md":
            continue
        m = POST_NAME.fullmatch(src.stem)
        if not m:
            raise SystemExit(f"{src}: post files are named YYYY-MM-DD-slug.md")
        meta, body = split_front_matter(src.read_text(encoding="utf-8"), src)
        if meta.get("draft"):
            continue
        for key in ("title", "summary"):
            if not isinstance(meta.get(key), str):
                raise SystemExit(f"{src}: front matter needs a {key}")
        date = dt.date.fromisoformat(m.group(1))
        if meta.get("date") not in (None, date):
            raise SystemExit(f"{src}: front matter date doesn't match the file name")
        posts.append(
            Post(src.stem, str(meta["title"]), date, str(meta["summary"]), md.render(body))
        )
    return sorted(posts, key=lambda p: (p.date, p.slug), reverse=True)


def render_blog(posts: list[Post], out: Path, shell: tuple[str, str], base: str) -> None:
    (out / "blog").mkdir(parents=True, exist_ok=True)
    feed_link = (
        '  <link rel="alternate" type="application/atom+xml" title="Garnet Guard blog" '
        'href="feed.xml">\n'
        if base
        else ""
    )
    for post in posts:
        meta = f'    <p class="meta"><time datetime="{post.date}">{post.date:%B} {post.date.day}, {post.date.year}</time></p>\n'
        text = page(
            shell,
            title=post.title,
            description=post.summary,
            crumbs='<a href="./">Blog</a>',
            meta=meta,
            body=post.html,
            extra_head=feed_link,
        )
        (out / "blog" / f"{post.slug}.html").write_text(text, encoding="utf-8")
    if posts:
        items = "\n".join(
            f'      <li><a href="{p.slug}">{html.escape(p.title)}</a> '
            f'<time datetime="{p.date}">{p.date}</time><br>{html.escape(p.summary)}</li>'
            for p in posts
        )
        body = f'    <h1>Blog</h1>\n    <ul class="posts">\n{items}\n    </ul>\n'
    else:
        body = (
            "    <h1>Blog</h1>\n"
            "    <p>No posts yet. The first one is the replay write-up: what Garnet Guard reports "
            "for each replayed compromise, with the false-positive rate next to the catch rate.</p>\n"
        )
    text = page(
        shell,
        title="Blog",
        description="Replays, incident notes and changes to Garnet Guard.",
        crumbs='<a href="../">Garnet Guard</a> / Blog',
        body=body,
        extra_head=feed_link,
    )
    (out / "blog" / "index.html").write_text(text, encoding="utf-8")
    if base:
        write_feed(posts, out / "blog" / "feed.xml", base)


def write_feed(posts: list[Post], path: Path, base: str) -> None:
    def esc(s: str) -> str:
        return html.escape(s, quote=True)

    updated = f"{posts[0].date}T00:00:00Z" if posts else "1970-01-01T00:00:00Z"
    entries = "".join(
        f"""  <entry>
    <title>{esc(p.title)}</title>
    <link href="{esc(f"{base}/blog/{p.slug}")}"/>
    <id>{esc(f"{base}/blog/{p.slug}")}</id>
    <updated>{p.date}T00:00:00Z</updated>
    <summary>{esc(p.summary)}</summary>
    <content type="html">{esc(p.html)}</content>
  </entry>
"""
        for p in posts
    )
    path.write_text(
        f"""<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>Garnet Guard</title>
  <link href="{esc(base)}/blog/"/>
  <link rel="self" href="{esc(base)}/blog/feed.xml"/>
  <id>{esc(base)}/blog/</id>
  <updated>{updated}</updated>
  <author><name>Garnet Guard</name></author>
{entries}</feed>
""",
        encoding="utf-8",
    )


def fix_landing_links(out: Path, built: set[str], has_index: bool) -> list[str]:
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
        return 'href="rules/"' if has_index else 'href="#rules"'

    text = re.sub(r'href="rules/(GRN-[A-Z]\d{3})"', repl, text)
    if not has_index:
        text = text.replace('href="rules/"', 'href="#rules"')
    path.write_text(text, encoding="utf-8")
    return sorted(set(missing))


def add_canonical(page_path: Path, url: str) -> None:
    tag = f'  <link rel="canonical" href="{html.escape(url)}">\n'
    text = page_path.read_text(encoding="utf-8")
    page_path.write_text(text.replace("</head>", tag + "</head>", 1), encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--rules", type=Path, default=REPO / "docs" / "rules")
    ap.add_argument("--blog", type=Path, default=REPO / "blog")
    ap.add_argument("--out", type=Path, default=SITE / "_build")
    ap.add_argument(
        "--base-url",
        default=os.environ.get("GARNET_SITE_URL", ""),
        help="e.g. https://example.org (no domain is decided yet)",
    )
    args = ap.parse_args()
    base = args.base_url.rstrip("/")

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

    shell = chrome((SITE / "index.html").read_text(encoding="utf-8"))
    md = MarkdownIt("commonmark", {"html": False}).enable("table")
    built, has_index = render_rules(args.rules, out, md, shell)
    posts = load_posts(args.blog, md)
    render_blog(posts, out, shell, base)
    missing = fix_landing_links(out, built, has_index)
    if not has_index:
        for page_path in (out / "blog").glob("*.html"):
            text = page_path.read_text(encoding="utf-8")
            page_path.write_text(
                text.replace('href="../rules/"', 'href="../#rules"'), encoding="utf-8"
            )

    if base:
        for page_path in out.rglob("*.html"):
            rel = page_path.relative_to(out).as_posix()
            path = rel.removesuffix("index.html").removesuffix(".html")
            add_canonical(page_path, f"{base}/{path}")
    else:
        print("note: no --base-url, so no canonical links and no blog feed", file=sys.stderr)
    if missing:
        print(
            f"warning: no rule page yet for {', '.join(missing)}; linked to the landing page instead",
            file=sys.stderr,
        )
    print(f"built {out} ({len(built)} rule pages, {len(posts)} posts)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
