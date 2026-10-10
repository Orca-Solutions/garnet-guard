# README header (light and dark)

GitHub renders the README in the viewer's theme, and the primary lockup sets `garnet` in ink, which disappears on a dark theme. A `<picture>` element with `prefers-color-scheme` is the documented switch, but it depends on the viewer's browser and GitHub theme agreeing, and it was seen failing on 2026-10-10 (GitHub dark dimmed showed the light lockup). So the header uses the switch for the dark lockup and falls back to the **plated lockup**, which reads on any background because it carries its own paper plate.

```html
<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/brand/lockup/lockup-horizontal-reverse.svg">
    <img src="docs/brand/lockup/lockup-horizontal-plate.svg" alt="Garnet Guard" width="380">
  </picture>
</p>
```

Rules:

- The fallback `<img>` is always the plated lockup, never the transparent one. Whatever the theme logic does, the fallback must read on dark.
- Paths are relative to the repo root so forks and branches keep working. Use the raw.githubusercontent.com URL only where a relative path cannot resolve (the PyPI long description, the PR comment).
- Width 380 keeps the lockup inside the plate at the same size as the 360-wide transparent lockup. Below 220 wide use `mark/mark-32.svg` with the H1 instead.
- The same snippet works for the PyPI README: PyPI renders only the fallback `<img>`, and the plate sits quietly on PyPI's white page.
- `lockup-horizontal-mono.svg` is for print, never for the README.
