# Garnet Guard brand kit

**Version 1.0. Signed off by Jason on 2026-10-10**: Garnet Guard, the pomegranate mark, garnet-700 as the primary colour. Incorporates the marketing thread's review and the extras chosen from the explorations page: the outline mark (`mark/mark-outline.svg`), the one-liner lockup and the seed full stop (`lockup/`), and two more stickers (`sticker/sticker-round-badge.svg`, `sticker-the-tell.svg`) alongside the die-cut mark. Everything here is generated from `generate.py`; change the tokens at the top of that file and rerun it rather than editing SVGs by hand. All text is outlined, so the files need no fonts installed.

## The idea

**Garnet** is named after the pomegranate (Latin *granatum*). The mark is a pomegranate opened by a delta, the symbol for a diff, so you can see the seeds. One seed is amber: the tell, the one thing in this release that differs from the last one you trusted. The story in one line: *we open every release and look at the seeds.*

## Name

*Confirmed by Jason on 2026-10-10: the name is Garnet Guard and the mark is the pomegranate. ADR-0007 can move to Accepted.*

- The public name is **Garnet Guard**, two words, both capitalised, in anything indexable: the README heading, the repository description, the PyPI summary, the GitHub Marketplace listing, talk titles, social accounts.
- **Garnet** alone is fine in running prose after the first mention in a document, and it is the CLI command (`garnet check`). Rule IDs stay `GRN-`.
- The wordmark is lowercase, `garnet guard`, and only the wordmark is lowercase.
- Never "GarnetGuard", "Garnet-Guard" or "garnet guard" in prose.

## The mark

| File | Use |
|---|---|
| `mark/mark-colour.svg` | Default. Garnet body, paper window, garnet seeds, amber tell. |
| `mark/mark-colour-on-white.svg` | Same with a white window, for pure-white pages. |
| `mark/mark-mono-ink.svg`, `mark-mono-garnet.svg` | One colour. The tell becomes a hollow seed so the story survives in mono. |
| `mark/mark-reverse.svg`, `mark-reverse-mono.svg` | On dark or garnet backgrounds. |
| `favicon/favicon-32.svg` | 32 px, three seeds. |
| `favicon/favicon-16.svg` | 16 px, one seed. Below 24 px, use this. |
| `avatar/avatar-512.svg` | GitHub org and bot avatar: paper mark on garnet. `avatar-512-ink.svg` is the dark variant. |

Construction is in `guides/construction.svg`: a 100-unit grid, body circle r 34, crown 20 units tall, window base 44 units, seeds r 5.6. Clear space is the crown height on every side (`guides/clearspace.svg`). Minimum size 16 px.

Do not: rotate it, outline it, add a gradient or drop shadow, recolour the tell to red or green, put it in a circle badge (the avatar file already handles that), or use more than one amber seed. If one seed is the tell, three are a pattern.

## Lockups

- `lockup/lockup-horizontal.svg` is the primary signature. Mark at left, `garnet` in ink, `guard` in garnet. The window is transparent, so it works on paper and white.
- `lockup-horizontal-reverse.svg` for dark backgrounds, `lockup-horizontal-mono.svg` for one-colour print.
- `lockup-horizontal-plate.svg` is the horizontal lockup on a paper plate with rounded corners. Use it wherever the background is unknown or can switch under the image (the GitHub README header, embeds in other people's pages). The plate is paper, so on a white page it is almost invisible; on a dark page it reads as a card.
- `lockup-stacked.svg` for square spaces, with the descriptor *release-diff guard* underneath.
- `wordmark-only.svg` where the mark already appears nearby (a page header next to the favicon).

The mark's height is 1.6 times the wordmark's cap height, with a gap of half the mark's width. Keep those ratios if you rebuild a lockup.

## Colour

`colour/palette.svg`, `tokens.css`, `tokens.json`.

| Token | Hex | Role |
|---|---|---|
| garnet-900 | #4A0C18 | Dark backgrounds, social preview |
| garnet-700 | #8E1B2C | The brand colour. The mark, `guard`, links |
| garnet-500 | #B4263A | Hover, emphasis |
| garnet-300 | #D9586A | Garnet on dark backgrounds |
| garnet-100 | #F6DEE1 | Tints, table stripes |
| amber | #E0A100 | **The tell.** Warnings and findings only. Never decoration. |
| ink | #1B1F24 | Text, dark UI |
| slate | #5C636B | Secondary text |
| paper | #F7F3EE | Light background |

Red is the brand, not "danger". A finding is amber. A pass is a quiet green if one is needed (`#2E7D4F` in the PR comment mock), never garnet. Contrast (WCAG): garnet-700 on paper 8.1:1, slate on paper 5.5:1, amber on garnet-900 6.8:1, all AA for body text. Garnet-300 on garnet-900 is 4.1:1, so on the darkest background use it for headings and large text only, and use paper for body text.

## Type

- **Display** (wordmark, headings): Inter Display, Bold, tracking -2%. Open licence, on Google Fonts as Inter with `opsz`.
- **Text**: Inter Regular and Medium.
- **Code and findings**: JetBrains Mono. Rule IDs, versions and file paths are always set in mono, the way the PR comment does it.

The wordmark is Inter Display Bold with its spacing tightened, outlined. A custom cut (a seed-shaped tittle on the i, a faceted g) is a later refinement if the brand earns it; Peters' advice is to evolve, not redraw.

## Pattern and imagery

- `pattern/seeds-dark.svg`, `seeds-light.svg`: arils (pomegranate seeds) drawn from the mark's seed geometry, each slightly irregular so the field reads as seeds rather than honeycomb, with one amber seed. Use at low contrast behind headers and on the social card. One amber seed per surface.
- `social/social-preview.svg`: GitHub's 1280×640 repository card. Three lines: the one-liner, what it is and where it runs, the tagline.
- `badge/checked-by-garnet-guard.svg` and `deps-checked-by-garnet-guard.svg`: README badges in the shields.io flat style for repos that run the Action. The wording is "checked by", never "guarded by" or "protected by", because the badge must not promise protection.

## The PR comment

The PR comment is the main brand surface (marketing §4). Two facts shape it: the free Action posts as **github-actions[bot]** with GitHub's grey avatar, and GitHub Markdown cannot set colour. So the brand lives in the comment's content, and the mock-ups show exactly what the free tool produces.

- `pr-comment/comment.md` is the Markdown template. Engineering can use it as the comment template directly; it carries the `<!-- garnet:report -->` marker from SPEC §9.4.
- `pr-comment/pr-comment-light.svg` and `pr-comment-dark.svg` are the renderings in GitHub's light and dark themes. These replace the old hero image.
- Structure: a bold header line with the 16 px mark inline (served from the repo, proxied by GitHub's camo, so it leaks nothing). Each flagged package in a `> [!WARNING]` block, which GitHub renders in its amber warning style. **Never `[!CAUTION]`**: it renders red. Rule IDs, versions and paths in inline code; each rule ID links to its docs page. Clean updates collapse into one `<details>` line, so a clean PR shows one quiet line. The footer, *Garnet Guard · what is this? · GRN-T001*, links only to docs.
- At launch, replace the example with a real comment from a real replay (lightning 2.6.2).

## Launch assets

| Asset | File | Notes |
|---|---|---|
| Backtest chart style | `charts/backtest-example-light.svg`, `-dark.svg` | Catch rate (ink) beside clean-corpus warn rate (amber) per rule, one axis, every bar labelled, legend present. Garnet is never a data colour. Amber on white is 2.2:1, so the value label on every bar is mandatory, not decoration. The figures in the file are examples; the launch chart uses the real replay numbers. |
| Terminal theme | `terminal/terminal-mock.svg`, `ansi.md` | Amber (33) for findings, green (32) for pass, bold header, bright-black notes, no red, `NO_COLOR` respected. The same theme for the README GIF. |
| Marketplace branding | `action.yml` | `branding: { icon: search, color: red }`. Marketplace only allows Feather icons and a fixed colour list, so the custom mark cannot appear; `search` is the loupe from the jeweller's-bench imagery. |
| Blog and incident-post header | `post/post-header-incident.svg`, `-changelog.svg` | Eyebrow (post type and date), title, small mark, tagline in the footer. No red bars, no "breaking" styling. |
| Talk slides | `slides/slide-title.svg`, `slide-content.svg` | Paper background, Inter Display headings, mono code block in ink, tagline and mark in the footer. For PyCon US 2027 and BSides. |
| Stickers | `sticker/sticker-diecut.svg`, `sticker-round-badge.svg`, `sticker-the-tell.svg` | The die-cut mark (3 in), the round badge with the tagline (2 in), and the lone amber seed (1 in). Three is a sheet. |
- Photography and illustration, if ever needed: real objects from the jeweller's bench (loupe, tweezers, a stone on a cloth) in natural light. Nothing from stock-security imagery: no padlocks, shields, hoodies, binary rain, glowing circuits, or AI sparkles.

## Voice

Garnet Guard sounds like a careful reviewer, not an alarm.

- **Calm.** "1 of 3 updates needs a look", never "THREAT DETECTED".
- **Exact.** Every claim carries its evidence: a rule ID, a file and line, an attestation field.
- **Honest about limits.** "Couldn't check" is said out loud. We never say "safe" or "secure"; a clean update is "pass" or "nothing worth a look".
- **Evidence or silence.** Never "would have caught" without a link to a replay. If a replay shows a miss, publish the miss.
- **A warning is a reason to look, not an accusation.** Never name an unconfirmed release as malicious in public (SECURITY.md, outreach.md's disclosure rule).
- **Plain.** Short sentences. Words we use: release, diff, provenance, trusted, review, explain, quiet. Words we don't: AI-powered, next-gen, zero-trust, firewall, military-grade, bulletproof.
- **Credit.** PyPI, Sigstore, OpenSSF, OSV and the researchers who documented each incident get named.

Tagline: **Trust the last release. Check the next.** Use it on the social card, stickers and slide footers. In technical channels (HN, Discourse, newsletters) lead with the one-liner instead; those readers want to know what it does in the first line. The pomegranate story belongs on the About page and in talk openers, not on the README's first screen.

## Messaging (owned by marketing)

The words come from the marketing plan, not from this kit. The kit only carries them. In particular:

- Repo description, Marketplace listing and the social card use marketing's recommended one-liner, *A second reviewer for every dependency update.* The README keeps the long sentence (*checks every dependency update against the last release you trusted...*).
- The three proof points (lightning, elementary-data, Shai-Hulud) are always concrete and always linked. No "would have caught" without a replay link.
- Lead with the false-positive rate next to the catch rate. No fear marketing, no breach-cost statistics.
- The PR comment is the ad (marketing §4, Tier 1), which is why `social/pr-comment-hero.svg` is the hero image everywhere and why the comment's footer, *Garnet Guard · what is this? · GRN-T001*, is treated as part of the identity. Any change to the comment layout goes past both the spec (SPEC §9.4) and marketing.
- The primary audience is maintainers of popular Python OSS, so the brand has to look at home in a GitHub PR next to zizmor and Dependabot: small, quiet, monospace where it counts.

## Files for the repo

When the repo is seeded, copy `` to `docs/brand/` and put the README header in a `<picture>` element that serves `lockup-horizontal-reverse.svg` to the dark theme with `lockup-horizontal-plate.svg` as the fallback (snippet and reasons in `guides/readme-header.md`). The transparent lockup is never the fallback: GitHub's theme switch does not always fire, and the ink `garnet` vanishes on dark. Set `social/social-preview.svg` (exported to PNG) as the repository social preview and `avatar/avatar-512.svg` (as PNG) as the org avatar. The Apache-2.0 licence covers the code; add a line to NOTICE that the name and mark are trademarks of the project, which is standard for Apache projects and keeps forks from shipping under the same mark.
