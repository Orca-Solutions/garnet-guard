"""Garnet Guard brand kit generator.
Usage: python3 brand.py <out-dir>
Everything is drawn on a 100-unit grid from the tokens below. Wordmark text is outlined
with Inter Display (SIL OFL) so the SVGs need no fonts installed."""
import math, os, sys, json
import uharfbuzz as hb
from fontTools.ttLib import TTFont
from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen

OUT = sys.argv[1]
TOK = {  # colour tokens; override any with BRAND_<KEY> in the environment (hyphen as underscore)
    "garnet-900": "#4A0C18", "garnet-700": "#8E1B2C", "garnet-500": "#B4263A", "garnet-300": "#D9586A",
    "garnet-100": "#F6DEE1", "amber": "#E0A100", "ink": "#1B1F24", "slate": "#5C636B", "paper": "#F7F3EE",
    "white": "#FFFFFF",
}
TOK = {k: os.environ.get("BRAND_" + k.upper().replace("-", "_"), v) for k, v in TOK.items()}
WORD1, WORD2 = os.environ.get("BRAND_WORD1", "garnet"), os.environ.get("BRAND_WORD2", "guard")
DESCRIPTOR = os.environ.get("BRAND_DESCRIPTOR", "RELEASE-DIFF GUARD"); TITLE = os.environ.get("BRAND_TITLE", "Garnet Guard")
G9, G7, G5, G3, G1 = TOK["garnet-900"], TOK["garnet-700"], TOK["garnet-500"], TOK["garnet-300"], TOK["garnet-100"]
AMBER, INK, SLATE, PAPER, WHITE = TOK["amber"], TOK["ink"], TOK["slate"], TOK["paper"], TOK["white"]
FONTDIR = "/usr/share/fonts/opentype/inter/"

def ensure(p): os.makedirs(os.path.dirname(p), exist_ok=True)
def W(name, s):
    p = os.path.join(OUT, name); ensure(p); open(p, "w").write(s)
def P(cx, cy, r, deg): a = math.radians(deg); return (cx + r*math.cos(a), cy + r*math.sin(a))
def pts(seq): return " ".join(f"{x:.2f},{y:.2f}" for x, y in seq)
def hexpts(cx, cy, r): return [P(cx, cy, r, 270 + 60*i) for i in range(6)]
def poly(seq, fill, extra=""): return f'<polygon points="{pts(seq)}" fill="{fill}" {extra}/>'
def circ(cx, cy, r, fill, extra=""): return f'<circle cx="{cx:.2f}" cy="{cy:.2f}" r="{r:.2f}" fill="{fill}" {extra}/>'
def svg(w, h, body, vb=None, bg=None):
    vb = vb or f"0 0 {w} {h}"
    b = f'<rect width="100%" height="100%" fill="{bg}"/>' if bg else ""
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{vb}" width="{w}" height="{h}" role="img" '
            f'aria-label="{TITLE}">{b}{body}</svg>\n')

# ---------- the mark: pomegranate + delta + seeds, on a 100-unit grid ----------
CROWN = [(37, 31), (40, 17), (45, 26), (50, 13), (55, 26), (60, 17), (63, 31)]
BODY = (50, 58, 34)
TRI = [(50, 38.5), (72, 76.5), (28, 76.5)]
SEEDS = [(50, 56.5), (42.5, 68.5), (57.5, 68.5)]
SEED_R = 5.6
TELL = 2  # index of the seed that differs

def mark(body=G7, window=PAPER, seed=G9, tell=AMBER, mono=False, seeds=3, tx=0, ty=0, s=1.0):
    """Returns SVG body. `mono` draws the tell seed hollow instead of coloured."""
    g = f'<g transform="translate({tx},{ty}) scale({s})">'
    if window == "none":
        # a real hole: body and crown wound one way, the window the other, nonzero fill
        def area(p): return sum(p[i][0]*p[(i+1)%len(p)][1] - p[(i+1)%len(p)][0]*p[i][1] for i in range(len(p)))/2
        crown = CROWN if area(CROWN) > 0 else CROWN[::-1]; tri = TRI if area(TRI) < 0 else TRI[::-1]
        cx, cy, r = BODY
        d = f"M{cx+r},{cy} A{r},{r} 0 1 1 {cx-r},{cy} A{r},{r} 0 1 1 {cx+r},{cy} Z "
        d += "M" + " L".join(f"{x},{y}" for x, y in crown) + " Z " + "M" + " L".join(f"{x},{y}" for x, y in tri) + " Z"
        g += f'<path d="{d}" fill="{body}" fill-rule="nonzero"/>'
    else:
        g += circ(*BODY, body) + poly(CROWN, body) + poly(TRI, window)
    if seeds == 1:
        g += poly(hexpts(50, 62, 8.5), seed)
    else:
        for i, (x, y) in enumerate(SEEDS):
            if i == TELL:
                if mono:
                    g += poly(hexpts(x, y, SEED_R), seed) + poly(hexpts(x, y, SEED_R-2.4), window)
                else:
                    g += poly(hexpts(x, y, SEED_R), tell)
            else:
                g += poly(hexpts(x, y, SEED_R), seed)
    return g + "</g>"

W("kit/mark/mark-colour.svg", svg(100, 100, mark()))
W("kit/mark/mark-colour-on-white.svg", svg(100, 100, mark(window=WHITE)))
W("kit/mark/mark-mono-ink.svg", svg(100, 100, mark(body=INK, window=WHITE, seed=INK, mono=True)))
W("kit/mark/mark-mono-garnet.svg", svg(100, 100, mark(body=G7, window=WHITE, seed=G7, mono=True)))
W("kit/mark/mark-reverse.svg", svg(100, 100, mark(body=PAPER, window=INK, seed=PAPER, tell=AMBER)))
W("kit/mark/mark-reverse-mono.svg", svg(100, 100, mark(body=WHITE, window="none", seed=WHITE, mono=True)))
# favicons: 32 keeps three seeds, 16 keeps one
W("kit/favicon/favicon-32.svg", svg(32, 32, mark(), vb="0 0 100 100"))
W("kit/favicon/favicon-16.svg", svg(16, 16, mark(seeds=1), vb="0 0 100 100"))
# avatar for the GitHub org / PR comment bot: paper mark on garnet
W("kit/avatar/avatar-512.svg", svg(512, 512, f'<rect width="512" height="512" fill="{G7}"/>'
    + mark(body=PAPER, window=G7, seed=PAPER, tell=AMBER, tx=76, ty=66, s=3.6)))
W("kit/avatar/avatar-512-ink.svg", svg(512, 512, f'<rect width="512" height="512" fill="{INK}"/>'
    + mark(body=G3, window=INK, seed=G3, tell=AMBER, tx=76, ty=66, s=3.6)))

# ---------- outlined text ----------
_fonts = {}
def font(file):
    if file not in _fonts:
        path = FONTDIR + file
        tt = TTFont(path); blob = hb.Blob.from_file_path(path); face = hb.Face(blob); f = hb.Font(face)
        _fonts[file] = (tt, f, tt.getGlyphSet(), tt["head"].unitsPerEm)
    return _fonts[file]

def text_path(s, file, size, x, y, fill, tracking=0.0, features=None):
    """Shape with HarfBuzz (real kerning), outline with fontTools, return <path> plus its advance width."""
    tt, f, gs, upm = font(file)
    buf = hb.Buffer(); buf.add_str(s); buf.guess_segment_properties()
    hb.shape(f, buf, features or {"kern": True, "liga": True})
    order = tt.getGlyphOrder(); k = size/upm
    d = ""; pen_x = 0
    for info, pos in zip(buf.glyph_infos, buf.glyph_positions):
        name = order[info.codepoint]
        sp = SVGPathPen(gs)
        tp = TransformPen(sp, (k, 0, 0, -k, x + (pen_x + pos.x_offset)*k, y - pos.y_offset*k))
        gs[name].draw(tp)
        d += sp.getCommands()
        pen_x += pos.x_advance + tracking*upm/size
    return f'<path d="{d}" fill="{fill}"/>', pen_x*k

DISPLAY = "InterDisplay-Bold.otf"; DISPLAY_MED = "InterDisplay-Medium.otf"; TEXT = "Inter-Regular.otf"; TEXT_MED = "Inter-Medium.otf"

def wordmark(x, y, size, ink=INK, red=G7, gap_ratio=0.26):
    p1, w1 = text_path(WORD1, DISPLAY, size, x, y, ink, tracking=-1.2)
    if not WORD2: return p1, w1
    p2, w2 = text_path(WORD2, DISPLAY, size, x + w1 + size*gap_ratio, y, red, tracking=-1.2)
    return p1 + p2, w1 + size*gap_ratio + w2

# horizontal lockup: mark height = cap height * 1.9, gap = 0.5 x mark unit
def lockup_h(ink, red, window, body, seed, tell=AMBER, mono=False):
    size = 56; mk = 0.9  # mark scale -> 90 units tall
    wm, ww = wordmark(112, 76, size, ink, red)
    total = 112 + ww + 10
    return svg(round(total), 100, mark(body, window, seed, tell, mono=mono, tx=4, ty=6, s=mk) + wm, vb=f"0 0 {total:.0f} 100")
W("kit/lockup/lockup-horizontal.svg", lockup_h(INK, G7, "none", G7, G9))
W("kit/lockup/lockup-horizontal-on-white.svg", lockup_h(INK, G7, WHITE, G7, G9))
W("kit/lockup/lockup-horizontal-mono.svg", lockup_h(INK, INK, WHITE, INK, INK, mono=True))
W("kit/lockup/lockup-horizontal-reverse.svg", lockup_h(PAPER, G3, INK, PAPER, PAPER))

def lockup_stacked(ink, red, window, body, seed, tell=AMBER, mono=False):
    size = 40
    wm, ww = wordmark(0, 0, size, ink, red)
    x = (240 - ww)/2
    wm, _ = wordmark(x, 174, size, ink, red)
    sub, sw = text_path(DESCRIPTOR, TEXT_MED, 9.5, 0, 0, SLATE if not mono else ink, tracking=2.2)
    sub, _ = text_path(DESCRIPTOR, TEXT_MED, 9.5, (240-sw)/2, 200, SLATE if not mono else ink, tracking=2.2)
    return svg(240, 220, mark(body, window, seed, tell, mono=mono, tx=70, ty=8, s=1.2) + wm + sub)
W("kit/lockup/lockup-stacked.svg", lockup_stacked(INK, G7, "none", G7, G9))
W("kit/lockup/lockup-stacked-reverse.svg", lockup_stacked(PAPER, G3, INK, PAPER, PAPER))
W("kit/lockup/wordmark-only.svg", (lambda wm_w: svg(round(wm_w[1])+8, 72, wm_w[0]))(wordmark(4, 56, 56, INK, G7)))

# ---------- construction + clear space ----------
def construction():
    b = f'<rect width="270" height="200" fill="{WHITE}"/>'
    # grid
    for i in range(0, 201, 10):
        b += f'<path d="M{i},0 V200 M0,{i} H200" stroke="{G1}" stroke-width="0.5"/>'
    b += f'<g opacity="0.9">{mark(body=G7, window=WHITE, seed=G9, tx=50, ty=50, s=1.0)}</g>'
    # guides: body circle, crown baseline, triangle, seed centres
    b += f'<circle cx="100" cy="108" r="34" fill="none" stroke="{INK}" stroke-width="0.6" stroke-dasharray="2 2"/>'
    b += f'<path d="M50,81 H150 M50,88.5 H150 M50,126.5 H150 M50,61 H150" stroke="{INK}" stroke-width="0.5" stroke-dasharray="2 2"/>'
    b += f'<path d="M100,40 V170" stroke="{INK}" stroke-width="0.5" stroke-dasharray="2 2"/>'
    for x, y in SEEDS: b += f'<circle cx="{x+50}" cy="{y+50}" r="{SEED_R}" fill="none" stroke="{INK}" stroke-width="0.5" stroke-dasharray="2 2"/>'
    lbl = lambda s, x, y: text_path(s, TEXT, 5, x, y, SLATE)[0]
    b += lbl("crown  20 u  (= x)", 152, 71) + lbl("body  r 34 u", 152, 109) + lbl("window  Δ  44 u base", 152, 128) + lbl("seeds  r 5.6 u", 152, 120)
    b += lbl("100 u grid", 50, 46)
    return svg(270, 200, b)
W("kit/guides/construction.svg", construction())

def clearspace():
    x = 20  # clear space = crown height
    b = f'<rect width="220" height="220" fill="{WHITE}"/>'
    b += f'<rect x="40" y="40" width="140" height="140" fill="none" stroke="{G3}" stroke-width="0.8" stroke-dasharray="3 2"/>'
    b += f'<rect x="60" y="60" width="100" height="100" fill="none" stroke="{G1}" stroke-width="0.8"/>'
    b += mark(body=G7, window=WHITE, seed=G9, tx=60, ty=60)
    for (x0, y0, x1, y1) in ((40, 30, 60, 30), (160, 30, 180, 30), (30, 40, 30, 60), (30, 160, 30, 180)):
        b += f'<path d="M{x0},{y0} L{x1},{y1}" stroke="{INK}" stroke-width="0.8"/>'
    lbl = lambda s, x, y: text_path(s, TEXT, 5.5, x, y, SLATE)[0]
    b += lbl("x", 48, 27) + lbl("x", 168, 27) + lbl("x", 24, 52) + lbl("x", 24, 172)
    b += lbl("x = crown height. Keep this much space clear on every side.", 40, 198)
    b += lbl("Minimum size: 16 px (favicon-16, one seed), 24 px for the three-seed mark.", 40, 208)
    return svg(220, 220, b)
W("kit/guides/clearspace.svg", clearspace())

# ---------- pattern ----------
def pattern(w=800, h=400, bg=G9, line=G7, tell_at=(3, 7)):
    b = f'<rect width="{w}" height="{h}" fill="{bg}"/>'
    r = 22; dx = r*math.sqrt(3); dy = r*1.5
    for row in range(-1, int(h/dy)+2):
        for col in range(-1, int(w/dx)+2):
            cx = col*dx + (dx/2 if row % 2 else 0); cy = row*dy
            if (row, col) == tell_at:
                b += poly(hexpts(cx, cy, r-4), AMBER)
            else:
                b += poly(hexpts(cx, cy, r-4), "none", f'stroke="{line}" stroke-width="1.5"')
    return svg(w, h, b)
W("kit/pattern/seeds-dark.svg", pattern())
W("kit/pattern/seeds-light.svg", pattern(bg=PAPER, line=G1, tell_at=(3, 7)))

# ---------- README badge (shields.io flat style, 20 px) ----------
def badge():
    l, lw = text_path("guarded by", "Inter-SemiBold.otf", 11, 22, 14, WHITE)
    r, rw = text_path("garnet guard", "Inter-SemiBold.otf", 11, 0, 0, WHITE)
    lw_box = 22 + lw + 6; total = lw_box + rw + 12
    r, _ = text_path("garnet guard", "Inter-SemiBold.otf", 11, lw_box + 6, 14, WHITE)
    b = (f'<rect width="{total:.0f}" height="20" rx="3" fill="{INK}"/>'
         f'<rect x="{lw_box:.0f}" width="{total-lw_box:.0f}" height="20" rx="3" fill="{G7}"/>'
         f'<rect x="{lw_box:.0f}" width="4" height="20" fill="{G7}"/>'
         + mark(body=WHITE, window=INK, seed=WHITE, tell=AMBER, tx=4, ty=2, s=0.16) + l + r)
    return svg(round(total), 20, b)
W("kit/badge/guarded-by-garnet-guard.svg", badge())

# ---------- social preview 1280x640 ----------
def social():
    b = f'<rect width="1280" height="640" fill="{G9}"/>'
    # pattern on the right, faded
    r = 30; dx = r*math.sqrt(3); dy = r*1.5
    for row in range(-1, 16):
        for col in range(0, 30):
            cx = 620 + col*dx + (dx/2 if row % 2 else 0); cy = row*dy
            if cx > 1300: continue
            if (row, col) == (6, 9): b += poly(hexpts(cx, cy, r-5), AMBER)
            else: b += poly(hexpts(cx, cy, r-5), "none", f'stroke="{G7}" stroke-width="1.5" stroke-opacity="0.8"')
    b += f'<rect width="1060" height="640" fill="url(#fade)"/>'
    b = (f'<defs><linearGradient id="fade" x1="0" x2="1"><stop offset="0.62" stop-color="{G9}"/><stop offset="1" stop-color="{G9}" stop-opacity="0"/></linearGradient></defs>' + b)
    b += mark(body=PAPER, window=G9, seed=PAPER, tell=AMBER, tx=96, ty=120, s=2.0)
    wm, _ = wordmark(330, 262, 92, PAPER, G3)
    b += wm
    t1, _ = text_path("A second reviewer for every", TEXT, 36, 100, 420, G1)
    t2, _ = text_path("dependency update.", TEXT, 36, 100, 466, G1)
    t3, _ = text_path("Open source · no telemetry · uvx garnet-guard", DISPLAY_MED, 22, 100, 540, G3)
    return svg(1280, 640, b + t1 + t2 + t3)
W("kit/social/social-preview.svg", social())

# ---------- PR comment hero ----------
def pr_hero():
    b = f'<rect width="1080" height="520" fill="{PAPER}"/>'
    b += f'<rect x="40" y="40" width="1000" height="440" rx="12" fill="{WHITE}" stroke="#D0D7DE" stroke-width="2"/>'
    b += f'<path d="M40,104 H1040" stroke="#D0D7DE" stroke-width="2"/><rect x="41" y="41" width="998" height="63" rx="11" fill="#F6F8FA"/>'
    b += f'<rect x="62" y="52" width="40" height="40" rx="20" fill="{G7}"/>' + mark(body=PAPER, window=G7, seed=PAPER, tx=66, ty=55, s=0.32)
    b += text_path("garnet-guard", "Inter-SemiBold.otf", 19, 114, 79, INK)[0] + text_path("bot", "Inter-Medium.otf", 12, 246, 78, SLATE)[0]
    b += text_path("commented 2 minutes ago", TEXT, 17, 290, 79, SLATE)[0]
    mono = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
    def m(s, x, y, fill=INK, size=18): return text_path(s, "../../truetype/dejavu/DejaVuSansMono.ttf", size, x, y, fill)[0]
    y = 150
    rows = [("Garnet Guard: 1 of 3 updates needs a look", INK), ("", INK),
            ("⚠ examplelib 2.6.1 → 2.6.2   WARN", "#9A6B00"),
            ("  GRN-T001  2.6.1 had a PyPI provenance attestation. 2.6.2 has none.", INK),
            ("  GRN-T004  No git tag v2.6.2 in github.com/example/examplelib.", INK),
            ("  GRN-C003  New import-time code in examplelib/__init__.py:12", INK), ("", INK),
            ("✓ requests 2.32.4 → 2.32.5   pass", "#2E7D4F"), ("✓ idna 3.10 → 3.11           pass", "#2E7D4F")]
    for s, c in rows:
        if s: b += m(s, 70, y, c)
        y += 32
    b += text_path("Garnet Guard · what is this? · GRN-T001", TEXT, 14, 70, y + 10, SLATE)[0]
    return svg(1080, 520, b)
W("kit/social/pr-comment-hero.svg", pr_hero())

# ---------- palette sheet ----------
def palette():
    sw = [("garnet-900", "Deep garnet. Dark backgrounds."), ("garnet-700", "Brand garnet. The mark, links, 'guard'."),
          ("garnet-500", "Hover and emphasis."), ("garnet-300", "Garnet on dark backgrounds."), ("garnet-100", "Tints, table stripes."),
          ("amber", "The tell. Warnings only."), ("ink", "Text, dark background."), ("slate", "Secondary text."), ("paper", "Light background.")]
    b = f'<rect width="900" height="260" fill="{WHITE}"/>'
    for i, (k, d) in enumerate(sw):
        x = 20 + i*97; c = TOK[k]
        b += f'<rect x="{x}" y="20" width="85" height="110" rx="8" fill="{c}" stroke="#00000018"/>'
        b += text_path(k, "Inter-SemiBold.otf", 12, x, 152, INK)[0] + text_path(c, "../../truetype/dejavu/DejaVuSansMono.ttf", 11, x, 170, SLATE)[0]
        words = d.split(" "); line = ""; yy = 190
        for wd in words:
            if len(line + wd) > 15: b += text_path(line, TEXT, 10.5, x, yy, SLATE)[0]; yy += 14; line = ""
            line += wd + " "
        b += text_path(line, TEXT, 10.5, x, yy, SLATE)[0]
    return svg(900, 260, b)
W("kit/colour/palette.svg", palette())
W("kit/colour/tokens.json", json.dumps({"color": TOK, "type": {"display": "Inter Display, Inter, system-ui, sans-serif",
    "text": "Inter, system-ui, sans-serif", "mono": "JetBrains Mono, SF Mono, Menlo, monospace"}}, indent=2) + "\n")
W("kit/colour/tokens.css", ":root {\n" + "".join(f"  --gg-{k}: {v};\n" for k, v in TOK.items())
  + "  --gg-font-display: 'Inter Display', Inter, system-ui, sans-serif;\n  --gg-font-text: Inter, system-ui, sans-serif;\n"
  "  --gg-font-mono: 'JetBrains Mono', 'SF Mono', Menlo, monospace;\n}\n")

# ---------- alternates kept from round 1 (Peters: develop the top three) ----------
def alt_delta_gem(fill=INK, line=WHITE, tx=0, ty=0, s=1.0):
    hv = {d: P(50, 52, 42, d) for d in (270, 330, 30, 90, 150, 210)}
    tv = {d: P(50, 55, 17, d) for d in (270, 30, 150)}
    g = f'<g transform="translate({tx},{ty}) scale({s})">' + poly([hv[d] for d in (270, 330, 30, 90, 150, 210)], fill) + poly([tv[270], tv[30], tv[150]], line)
    d = ""
    for h, t in ((270, 270), (30, 30), (150, 150)): d += f"M{hv[h][0]:.2f},{hv[h][1]:.2f} L{tv[t][0]:.2f},{tv[t][1]:.2f} "
    mids = {330: ((tv[270][0]+tv[30][0])/2, (tv[270][1]+tv[30][1])/2), 90: ((tv[30][0]+tv[150][0])/2, (tv[30][1]+tv[150][1])/2), 210: ((tv[150][0]+tv[270][0])/2, (tv[150][1]+tv[270][1])/2)}
    for h, m in mids.items(): d += f"M{hv[h][0]:.2f},{hv[h][1]:.2f} L{m[0]:.2f},{m[1]:.2f} "
    return g + f'<path d="{d}" stroke="{line}" stroke-width="2.4" fill="none"/></g>'
def alt_marquise(fill=INK, line=WHITE, tx=0, ty=0, s=1.0):
    g = f'<g transform="translate({tx},{ty}) scale({s})"><path d="M6,50 A54,54 0 0 1 94,50 A54,54 0 0 1 6,50 Z" fill="{fill}"/>'
    g += f'<path d="M6,50 L34,40 L66,40 L94,50 L66,60 L34,60 Z" fill="none" stroke="{line}" stroke-width="2.4"/>'
    g += circ(50, 50, 10, line) + circ(50, 50, 5.5, fill) + "</g>"
    return g
W("alternates/delta-gem.svg", svg(100, 100, alt_delta_gem()))
W("alternates/marquise-eye.svg", svg(100, 100, alt_marquise()))
for name, fn in (("delta-gem", alt_delta_gem), ("marquise-eye", alt_marquise)):
    wm, ww = wordmark(112, 76, 56, INK, INK)
    W(f"alternates/{name}-lockup.svg", svg(round(122+ww), 100, fn(tx=4, ty=6, s=0.9) + wm, vb=f"0 0 {122+ww:.0f} 100"))
wm, ww = wordmark(112, 76, 56, INK, INK)
W("alternates/pomegranate-lockup.svg", svg(round(122+ww), 100, mark(body=INK, window=WHITE, seed=INK, mono=True, tx=4, ty=6, s=0.9) + wm, vb=f"0 0 {122+ww:.0f} 100"))
W("alternates/pomegranate.svg", svg(100, 100, mark(body=INK, window=WHITE, seed=INK, mono=True)))
print("done")

# =====================================================================
# Revision 2 (after marketing review, 2026-10-10)
# =====================================================================
import random
MONO_TTF = "../../truetype/dejavu/DejaVuSansMono.ttf"
def T(s, file, size, x, y, fill, tracking=0.0): return text_path(s, file, size, x, y, fill, tracking)[0]
def TW(s, file, size, tracking=0.0): return text_path(s, file, size, 0, 0, "#000", tracking)[1]

# ---------- arils: seed cells that look like seeds, not honeycomb ----------
def aril(cx, cy, r, seed, fill="none", stroke=None, sw=1.5):
    rnd = random.Random(seed)
    rr = r*rnd.uniform(0.70, 0.92); rot = rnd.uniform(-28, 28)
    p = [P(cx, cy, rr*rnd.uniform(0.86, 1.0), rot + 270 + 60*i) for i in range(6)]
    st = f'stroke="{stroke}" stroke-width="{sw}" stroke-linejoin="round"' if stroke else ""
    if fill != "none" and not stroke:  # rounded solid: stroke in the fill colour
        st = f'stroke="{fill}" stroke-width="{r*0.5:.1f}" stroke-linejoin="round"'
    return poly(p, fill, st)
def aril_field(x0, y0, w, h, r, line, bg_tell=AMBER, tell=None, sw=1.5, seed=7):
    b = ""; dx = r*math.sqrt(3); dy = r*1.5; k = 0
    for row in range(-1, int(h/dy)+2):
        for col in range(-1, int(w/dx)+2):
            cx = x0 + col*dx + (dx/2 if row % 2 else 0); cy = y0 + row*dy; k += 1
            if (row, col) == tell: b += aril(cx, cy, r-3, seed+k, fill=bg_tell)
            else: b += aril(cx, cy, r-3, seed+k, stroke=line, sw=sw*1.8)
    return b
W("kit/pattern/seeds-dark.svg", svg(800, 400, f'<rect width="800" height="400" fill="{G9}"/>' + aril_field(0, 0, 800, 400, 24, G7, tell=(5, 9))))
W("kit/pattern/seeds-light.svg", svg(800, 400, f'<rect width="800" height="400" fill="{PAPER}"/>' + aril_field(0, 0, 800, 400, 24, G1, tell=(5, 9))))
if os.environ.get("BRAND_MINIMAL") == "1":
    for f in ("kit/social/social-preview.svg", "kit/social/pr-comment-hero.svg", "kit/badge/guarded-by-garnet-guard.svg"):
        p = os.path.join(OUT, f); os.path.exists(p) and os.remove(p)
    print("minimal done"); sys.exit(0)

# ---------- social preview v2 ----------
def social2():
    b = f'<defs><linearGradient id="fade" x1="0" x2="1"><stop offset="0.6" stop-color="{G9}"/><stop offset="1" stop-color="{G9}" stop-opacity="0"/></linearGradient></defs>'
    b += f'<rect width="1280" height="640" fill="{G9}"/>'
    b += aril_field(600, 0, 700, 640, 32, G7, tell=(6, 11), sw=1.8)
    b += f'<rect width="1080" height="640" fill="url(#fade)"/>'
    b += mark(body=PAPER, window=G9, seed=PAPER, tell=AMBER, tx=96, ty=96, s=1.9)
    wm, _ = wordmark(316, 232, 88, PAPER, G3); b += wm
    b += T("A second reviewer for every", TEXT, 38, 100, 372, PAPER) + T("dependency update.", TEXT, 38, 100, 420, PAPER)
    b += T("Free, open-source GitHub Action and CLI for Python dependency updates.", TEXT, 24, 100, 486, G1)
    b += T("Trust the last release. Check the next.", DISPLAY_MED, 22, 100, 560, G3)
    return svg(1280, 640, b)
W("kit/social/social-preview.svg", social2())

# ---------- README badge v2 ----------
def badge2(label="checked by"):
    l, lw = text_path(label, "Inter-SemiBold.otf", 11, 22, 14, WHITE)
    rw = TW("garnet guard", "Inter-SemiBold.otf", 11)
    lw_box = 22 + lw + 6; total = lw_box + rw + 12
    r = T("garnet guard", "Inter-SemiBold.otf", 11, lw_box + 6, 14, WHITE)
    b = (f'<rect width="{total:.0f}" height="20" rx="3" fill="{INK}"/><rect x="{lw_box:.0f}" width="{total-lw_box:.0f}" height="20" rx="3" fill="{G7}"/>'
         f'<rect x="{lw_box:.0f}" width="4" height="20" fill="{G7}"/>' + mark(body=WHITE, window=INK, seed=WHITE, tell=AMBER, tx=4, ty=2, s=0.16) + l + r)
    return svg(round(total), 20, b)
W("kit/badge/checked-by-garnet-guard.svg", badge2())
W("kit/badge/deps-checked-by-garnet-guard.svg", badge2("deps checked by"))
os.remove(os.path.join(OUT, "kit/badge/guarded-by-garnet-guard.svg")) if os.path.exists(os.path.join(OUT, "kit/badge/guarded-by-garnet-guard.svg")) else None

# ---------- the real PR comment, as GitHub renders it ----------
COMMENT_MD = """<!-- garnet:report -->
<img src="https://raw.githubusercontent.com/orca-solutions/garnet-guard/main/docs/brand/favicon/favicon-16.svg" width="16" height="16" alt=""> **Garnet Guard: 1 of 3 updates needs a look**

> [!WARNING]
> **examplelib 2.6.1 → 2.6.2**
> - [`GRN-T001`](https://garnet-guard.dev/rules/GRN-T001) 2.6.1 had a PyPI provenance attestation from `github.com/example/examplelib` (`release.yml`). 2.6.2 has none.
> - [`GRN-T004`](https://garnet-guard.dev/rules/GRN-T004) No git tag `v2.6.2` exists in `github.com/example/examplelib`.
> - [`GRN-C003`](https://garnet-guard.dev/rules/GRN-C003) New import-time code in `examplelib/__init__.py:12` (subprocess call at module level).

<details><summary>2 updates with nothing worth a look</summary>

| Package | Update | Checks |
|---|---|---|
| `requests` | 2.32.4 → 2.32.5 | provenance ✓ · tag ✓ · content ✓ |
| `idna` | 3.10 → 3.11 | provenance ✓ · tag ✓ · content ✓ |

</details>

<sub>Garnet Guard · [what is this?](https://garnet-guard.dev/what) · [GRN-T001](https://garnet-guard.dev/rules/GRN-T001) · [GRN-T004](https://garnet-guard.dev/rules/GRN-T004) · [GRN-C003](https://garnet-guard.dev/rules/GRN-C003)</sub>
"""
W("kit/pr-comment/comment.md", COMMENT_MD)

def pr_comment(dark=False):
    if dark: bg, border, fg, muted, code, link, warn, hdr = "#0D1117", "#30363D", "#E6EDF3", "#8B949E", "#2A3038", "#4493F8", "#D29922", "#161B22"
    else:    bg, border, fg, muted, code, link, warn, hdr = "#FFFFFF", "#D0D7DE", "#1F2328", "#656D76", "#EFF1F3", "#0969DA", "#9A6700", "#F6F8FA"
    page = "#0D1117" if dark else PAPER
    b = f'<rect width="1080" height="HHH" fill="{page}"/>'
    b += f'<rect x="40" y="36" width="1000" height="BBB" rx="8" fill="{bg}" stroke="{border}" stroke-width="1.5"/>'
    b += f'<path d="M41,92 H1039" stroke="{border}" stroke-width="1.5"/><rect x="41" y="37" width="998" height="54" rx="7" fill="{hdr}"/><rect x="41" y="80" width="998" height="12" fill="{hdr}"/>'
    # generic github-actions avatar: grey circle, the free Action's real identity
    b += f'<circle cx="74" cy="64" r="14" fill="#8B949E"/><circle cx="74" cy="64" r="9" fill="{hdr}"/><circle cx="74" cy="64" r="4" fill="#8B949E"/>'
    b += T("github-actions", "Inter-SemiBold.otf", 16, 98, 70, fg) + f'<rect x="222" y="54" width="34" height="20" rx="10" fill="none" stroke="{border}"/>' + T("bot", TEXT_MED, 11, 229, 68, muted)
    b += T("commented 2 minutes ago", TEXT, 15, 266, 70, muted)
    y = 130
    b += mark(body=G7 if not dark else G3, window=bg, seed=G7 if not dark else G3, tell=AMBER, tx=70, ty=y-16, s=0.2) + T("Garnet Guard: 1 of 3 updates needs a look", "Inter-SemiBold.otf", 17, 98, y, fg)
    # [!WARNING] alert
    y += 30
    b += f'<rect x="70" y="{y}" width="4" height="150" rx="2" fill="{warn}"/>'
    b += f'<path d="M92,{y+26} l6,-11 l6,11 z M98,{y+19} v4 M98,{y+24.5} v0.1" fill="none" stroke="{warn}" stroke-width="1.8" stroke-linejoin="round"/>' + T("Warning", "Inter-SemiBold.otf", 15, 108, y+26, warn)
    y += 56
    b += T("examplelib 2.6.1 → 2.6.2", "Inter-SemiBold.otf", 16, 92, y, fg)
    def codechip(s, x, yy, fill=link):
        w = TW(s, MONO_TTF, 13.5) + 10
        return f'<rect x="{x}" y="{yy-14}" width="{w:.0f}" height="20" rx="4" fill="{code}"/>' + T(s, MONO_TTF, 13.5, x+5, yy, fill), w
    rows = [("GRN-T001", "2.6.1 had a PyPI provenance attestation from ", "github.com/example/examplelib", ". 2.6.2 has none."),
            ("GRN-T004", "No git tag ", "v2.6.2", " exists in github.com/example/examplelib."),
            ("GRN-C003", "New import-time code in ", "examplelib/__init__.py:12", " (subprocess call at module level).")]
    for rid, pre, cd, post in rows:
        y += 30; x = 92
        b += f'<circle cx="{x+3}" cy="{y-5}" r="2.2" fill="{fg}"/>'; x += 14
        c, w = codechip(rid, x, y); b += c; x += w + 6
        b += T(pre, TEXT, 15, x, y, fg); x += TW(pre, TEXT, 15)
        c, w = codechip(cd, x, y, fg); b += c; x += w + 2
        b += T(post, TEXT, 15, x, y, fg)
    # details
    y += 58
    b += f'<path d="M{76},{y-9} l5,4 l-5,4 z" fill="{muted}"/>' + T("2 updates with nothing worth a look", TEXT, 15, 90, y, fg)
    # footer
    y += 50
    b += f'<path d="M70,{y-26} H1010" stroke="{border}" stroke-width="1"/>'
    x = 70
    for s, col in (("Garnet Guard", muted), ("  ·  ", muted), ("what is this?", link), ("  ·  ", muted), ("GRN-T001", link), ("  ·  ", muted), ("GRN-T004", link), ("  ·  ", muted), ("GRN-C003", link)):
        b += T(s, TEXT, 13, x, y, col); x += TW(s, TEXT, 13)
    H = y + 56; b = b.replace("HHH", str(H)).replace("BBB", str(H - 72))
    return svg(1080, H, b)
W("kit/pr-comment/pr-comment-light.svg", pr_comment(False))
W("kit/pr-comment/pr-comment-dark.svg", pr_comment(True))
if os.path.exists(os.path.join(OUT, "kit/social/pr-comment-hero.svg")): os.remove(os.path.join(OUT, "kit/social/pr-comment-hero.svg"))

# ---------- backtest chart style ----------
RULES = [("GRN-T001", 100, 1.2), ("GRN-T002", 100, 0.4), ("GRN-T004", 83, 3.1), ("GRN-C001", 67, 0.2), ("GRN-C003", 100, 2.6), ("GRN-C005", 50, 0.0), ("GRN-K001", 100, 0.0)]
def chart(dark=False):
    bg = INK if dark else WHITE; fg = PAPER if dark else INK; mut = "#A9AFB7" if dark else SLATE; grid = "#343A42" if dark else "#E8E2DB"
    catch = "#D8CFC6" if dark else INK
    W_, H_ = 900, 470; x0, y0, x1, y1 = 70, 80, 870, 380
    b = f'<rect width="{W_}" height="{H_}" fill="{bg}"/>'
    b += T("Replay results per rule", "Inter-SemiBold.otf", 18, 24, 34, fg) + T("Catch rate on the 2025–26 incident corpus, and warn rate on 500 clean releases. Example data.", TEXT, 13, 24, 56, mut)
    for v in (0, 25, 50, 75, 100):
        yy = y1 - (y1-y0)*v/100
        b += f'<path d="M{x0},{yy} H{x1}" stroke="{grid}" stroke-width="1"/>' + T(f"{v}%", TEXT, 12, x0-10-TW(f"{v}%", TEXT, 12), yy+4, mut)
    n = len(RULES); slot = (x1-x0)/n; bw = 26
    for i, (rid, c, wr) in enumerate(RULES):
        cx = x0 + slot*(i+0.5)
        for j, (val, col) in enumerate(((c, catch), (wr, AMBER))):
            x = cx - bw - 1 + j*(bw+2); h = (y1-y0)*val/100; yy = y1 - h
            if val > 0: b += f'<rect x="{x:.1f}" y="{yy:.1f}" width="{bw}" height="{h:.1f}" rx="3" fill="{col}"/><rect x="{x:.1f}" y="{y1-3}" width="{bw}" height="3" fill="{col}"/>'
            else: b += f'<rect x="{x:.1f}" y="{y1-2}" width="{bw}" height="2" fill="{col}"/>'
            lbl = f"{val:g}%"; b += T(lbl, TEXT_MED, 11, x + bw/2 - TW(lbl, TEXT_MED, 11)/2, yy-6, fg if j == 0 else fg)
        b += T(rid, MONO_TTF, 12, cx - TW(rid, MONO_TTF, 12)/2, y1+22, fg)
    b += f'<path d="M{x0},{y1} H{x1}" stroke="{mut}" stroke-width="1"/>'
    ly = 428
    b += f'<rect x="{x0}" y="{ly-10}" width="12" height="12" rx="2" fill="{catch}"/>' + T("Catch rate (incident corpus)", TEXT, 13, x0+18, ly, fg)
    b += f'<rect x="{x0+230}" y="{ly-10}" width="12" height="12" rx="2" fill="{AMBER}"/>' + T("Warn rate on clean releases (lower is better)", TEXT, 13, x0+248, ly, fg)
    b += T("garnet-guard replay · corpus v1 · example figures, not results", TEXT, 11, x0, 456, mut)
    return svg(W_, H_, b)
W("kit/charts/backtest-example-light.svg", chart(False))
W("kit/charts/backtest-example-dark.svg", chart(True))

# ---------- terminal theme ----------
def terminal():
    bg, fg, mut, amber, green, bold = "#1B1F24", "#E6E1DA", "#8A9099", "#F0B429", "#5DBB7A", "#FFFFFF"
    b = f'<rect width="900" height="430" rx="10" fill="{bg}"/>'
    for i, c in enumerate(("#FF5F57", "#FEBC2E", "#28C840")): b += f'<circle cx="{24+i*20}" cy="22" r="6" fill="{c}"/>'
    lines = [("$ uvx garnet-guard check --git-base origin/main", fg), ("", fg),
             ("Garnet Guard  3 updates checked, 1 needs a look", bold), ("", fg),
             ("⚠ examplelib 2.6.1 → 2.6.2                        WARN", amber),
             ("  GRN-T001  2.6.1 had a PyPI provenance attestation. 2.6.2 has none.", fg),
             ("  GRN-T004  No git tag v2.6.2 in github.com/example/examplelib.", fg),
             ("  GRN-C003  New import-time code in examplelib/__init__.py:12", fg), ("", fg),
             ("✓ requests 2.32.4 → 2.32.5                         pass", green),
             ("✓ idna 3.10 → 3.11                                 pass", green), ("", fg),
             ("Couldn't check: 0.  Run `garnet explain GRN-T001` for details.", mut)]
    y = 66
    for s, c in lines:
        if s: b += T(s, MONO_TTF, 15, 24, y, c)
        y += 27
    return svg(900, 430, b)
W("kit/terminal/terminal-mock.svg", terminal())
W("kit/terminal/ansi.md", """# Garnet Guard terminal colours

| Element | ANSI | Hex (for docs, GIFs and asciinema themes) |
|---|---|---|
| Header line, package names | bold (1) | #FFFFFF on dark, ink on light |
| Finding, WARN verdict | yellow (33), bold for the verdict | #F0B429 (amber, lifted for dark terminals) |
| pass verdict | green (32) | #5DBB7A |
| Rule IDs, versions, paths | default, never coloured | |
| Secondary notes, "couldn't check" | bright black (90) | #8A9099 |
| BLOCK verdict | bold yellow, never red | |

Rules: respect `NO_COLOR` and `--no-color`; detect a non-TTY and print plain text; never use red (31), it is the brand, not the alarm; never print "safe".
Asciinema theme: background #1B1F24, foreground #E6E1DA, palette above.
""")

# ---------- blog / incident-post header ----------
def post_header(eyebrow, title1, title2, date):
    b = f'<rect width="1200" height="320" fill="{PAPER}"/>'
    b += mark(body=G7, window=PAPER, seed=G9, tx=64, ty=56, s=0.72)
    b += T(eyebrow.upper(), TEXT_MED, 14, 160, 88, G7, tracking=2.5) + T(date, TEXT, 14, 160 + TW(eyebrow.upper(), TEXT_MED, 14, 2.5) + 24, 88, SLATE)
    b += T(title1, DISPLAY, 50, 160, 160, INK, tracking=-1) + T(title2, DISPLAY, 50, 160, 218, INK, tracking=-1)
    b += f'<path d="M64,272 H1136" stroke="{G1}" stroke-width="2"/>' + T("garnet-guard.dev", TEXT, 14, 64, 300, SLATE) + T("Trust the last release. Check the next.", TEXT_MED, 14, 1136 - TW("Trust the last release. Check the next.", TEXT_MED, 14), 300, G7)
    return svg(1200, 320, b)
W("kit/post/post-header-incident.svg", post_header("Incident replay", "Would Garnet Guard have caught", "lightning 2.6.2?", "2026-04-18"))
W("kit/post/post-header-changelog.svg", post_header("Changelog", "October: three new rules,", "two false positives fixed", "2026-10-31"))

# ---------- slides ----------
def slide_title():
    b = f'<rect width="1920" height="1080" fill="{PAPER}"/>'
    b += mark(body=G7, window=PAPER, seed=G9, tx=160, ty=200, s=3.2)
    wm, _ = wordmark(560, 420, 120, INK, G7); b += wm
    b += T("What changed between releases in the 2025–26 PyPI compromises", DISPLAY_MED, 44, 560, 520, INK, tracking=-0.5)
    b += T("Jason Fricano · PyCon US 2027", TEXT, 28, 560, 580, SLATE)
    b += f'<path d="M160,940 H1760" stroke="{G1}" stroke-width="3"/>' + T("Trust the last release. Check the next.", TEXT_MED, 22, 160, 990, G7) + T("garnet-guard.dev", TEXT, 22, 1760 - TW("garnet-guard.dev", TEXT, 22), 990, SLATE)
    return svg(1920, 1080, b)
def slide_content():
    b = f'<rect width="1920" height="1080" fill="{PAPER}"/>'
    b += T("Three signals a machine can check", DISPLAY, 60, 160, 180, INK, tracking=-1)
    for i, (h, s) in enumerate((("Trust downgrade", "The attestation, publisher or git tag that the last release had is missing."),
                                ("Risky content change", "A new .pth file, build hook, or import-time exec, subprocess or network call."),
                                ("Known bad", "The release matches an OSV or OpenSSF malicious-package advisory."))):
        y = 300 + i*150
        b += poly(hexpts(190, y-10, 16), AMBER if i == 1 else G7) + T(h, "Inter-SemiBold.otf", 36, 240, y, INK) + T(s, TEXT, 28, 240, y+44, SLATE)
    b += f'<rect x="160" y="760" width="1600" height="130" rx="10" fill="{INK}"/>'
    b += T("GRN-T001  2.6.1 had a PyPI provenance attestation. 2.6.2 has none.", MONO_TTF, 26, 190, 815, "#F0B429") + T("GRN-C003  New import-time code in lightning/__init__.py:12", MONO_TTF, 26, 190, 860, "#E6E1DA")
    b += f'<path d="M160,940 H1760" stroke="{G1}" stroke-width="3"/>' + mark(body=G7, window=PAPER, seed=G9, tx=160, ty=955, s=0.5) + T("Trust the last release. Check the next.", TEXT_MED, 22, 230, 990, G7) + T("12", TEXT, 22, 1760 - TW("12", TEXT, 22), 990, SLATE)
    return svg(1920, 1080, b)
W("kit/slides/slide-title.svg", slide_title())
W("kit/slides/slide-content.svg", slide_content())

# ---------- sticker (die-cut, 3 in at 100 units = 3 in) ----------
def sticker():
    b = f'<rect width="120" height="120" fill="#E9E9E9"/>'
    halo = circ(60, 68, 38, WHITE) + poly([(x+10, y+10) for x, y in CROWN], WHITE, f'stroke="{WHITE}" stroke-width="7" stroke-linejoin="round"') + circ(60, 68, 37.5, WHITE, f'stroke="{WHITE}" stroke-width="7"')
    b += halo + mark(body=G7, window=WHITE, seed=G9, tx=10, ty=10)
    b += circ(60, 68, 41.5, "none", f'stroke="{G3}" stroke-width="0.5" stroke-dasharray="2 1.5"') + poly([(x+10, y+10) for x, y in CROWN], "none", f'stroke="{G3}" stroke-width="0.5" stroke-dasharray="2 1.5" stroke-linejoin="round" transform="translate(0,-4)"')
    b += T("3 in · die-cut on the dashed line · 4 mm white bleed", TEXT, 4, 10, 116, SLATE)
    return svg(120, 120, b)
W("kit/sticker/sticker-diecut.svg", sticker())
print("rev2 done")

# =====================================================================
# Explorations (Jason, 2026-10-10): garnet shades, mark variants, stickers
# =====================================================================
SHADES = [("garnet-700 (current)", "#8E1B2C", "#4A0C18"), ("pyrope", "#7A1020", "#3E0810"), ("almandine", "#601424", "#2E0810"), ("rhodolite", "#9B1E48", "#4C0C24"), ("spessartine", "#A8301E", "#4E1008")]
for name, body, deep in SHADES:
    slug = name.split(" ")[0]
    W(f"explore/shade-{slug}.svg", svg(100, 100, mark(body=body, window=PAPER, seed=deep, tell=AMBER)))
    W(f"explore/shade-{slug}-dark.svg", svg(100, 100, f'<rect width="100" height="100" fill="{INK}"/>' + mark(body=body, window=INK, seed=PAPER, tell=AMBER)))

# mark variants
def variant_seedcluster():
    g = circ(*BODY, G7) + poly(CROWN, G7) + circ(50, 62, 20, PAPER)
    r = 6.2; dx = r*math.sqrt(3); dy = r*1.5; k = 0
    for row in range(-2, 3):
        for col in range(-2, 3):
            x = 50 + col*dx + (dx/2 if row % 2 else 0); y = 62 + row*dy; k += 1
            if math.hypot(x-50, y-62) <= 15: g += aril(x, y, r-0.8, 40+k, fill=AMBER if (row, col) == (1, 0) else G9)
    return g
def variant_half():
    # cross-section: half fruit, arils filling the window
    g = circ(*BODY, G7) + poly(CROWN, G7)
    g += f'<path d="M22,58 A28,28 0 0 0 78,58 Z" fill="{PAPER}"/>'
    r = 5.6; dx = r*math.sqrt(3); dy = r*1.5; k = 0
    for row in range(0, 4):
        for col in range(-4, 5):
            x = 50 + col*dx + (dx/2 if row % 2 else 0); y = 62 + row*dy; k += 1
            if math.hypot(x-50, y-58) <= 23 and y > 60: g += aril(x, y, r-0.8, 80+k, fill=AMBER if (row, col) == (1, 1) else G9)
    return g
def variant_single():
    return circ(*BODY, G7) + poly(CROWN, G7) + poly(TRI, PAPER) + poly(hexpts(50, 62, 9), G9) + poly(hexpts(50, 62, 4), AMBER)
def variant_crown3():
    crown = [(38, 31), (41, 15), (50, 24), (59, 15), (62, 31)]
    return circ(*BODY, G7) + poly(crown, G7) + poly(TRI, PAPER) + "".join(poly(hexpts(x, y, SEED_R), AMBER if i == TELL else G9) for i, (x, y) in enumerate(SEEDS))
def variant_outline():
    g = circ(*BODY, "none", f'stroke="{G7}" stroke-width="5"') + poly(CROWN, PAPER, f'stroke="{G7}" stroke-width="5" stroke-linejoin="round"') + circ(*BODY[:2], 34-2.5, PAPER) 
    g = circ(*BODY, PAPER, f'stroke="{G7}" stroke-width="5"') + poly(CROWN, PAPER, f'stroke="{G7}" stroke-width="5" stroke-linejoin="round"') + poly([(37, 31), (63, 31), (63, 36), (37, 36)], PAPER)
    g += poly(TRI, "none", f'stroke="{G7}" stroke-width="4" stroke-linejoin="round"') + "".join(poly(hexpts(x, y, SEED_R), AMBER if i == TELL else G7) for i, (x, y) in enumerate(SEEDS))
    return g
for n, fn in (("delta-three-seeds", lambda: mark()), ("seed-cluster", variant_seedcluster), ("cross-section", variant_half), ("single-seed", variant_single), ("three-point-crown", variant_crown3), ("outline", variant_outline)):
    W(f"explore/variant-{n}.svg", svg(100, 100, fn()))

# curved text for badges
def arc_text(s, cx, cy, r, start_deg, file, size, fill, tracking=0.0, flip=False):
    tt, f, gs, upm = font(file)
    buf = hb.Buffer(); buf.add_str(s); buf.guess_segment_properties(); hb.shape(f, buf, {"kern": True})
    order = tt.getGlyphOrder(); k = size/upm
    advs = [(order[i.codepoint], p.x_advance*k + tracking) for i, p in zip(buf.glyph_infos, buf.glyph_positions)]
    total = sum(a for _, a in advs); out = ""; dist = 0
    for name, adv in advs:
        mid = dist + adv/2
        ang = start_deg + (mid/r)*(180/math.pi) * (-1 if flip else 1)
        a = math.radians(ang); x = cx + r*math.cos(a); y = cy + r*math.sin(a)
        rot = ang + (90 if not flip else -90)
        sp = SVGPathPen(gs); tp = TransformPen(sp, (k, 0, 0, -k, -adv/2 + tracking/2, 0)); gs[name].draw(tp)
        out += f'<path d="{sp.getCommands()}" fill="{fill}" transform="translate({x:.2f},{y:.2f}) rotate({rot:.2f})"/>'
        dist += adv
    return out, total

def sticker_round():
    b = f'<rect width="200" height="200" fill="#E9E9E9"/>'
    b += circ(100, 100, 92, G7) + circ(100, 100, 85, "none", f'stroke="{PAPER}" stroke-width="1.5"')
    b += mark(body=PAPER, window=G7, seed=PAPER, tell=AMBER, tx=62, ty=52, s=0.78)
    top, _ = arc_text("TRUST THE LAST RELEASE", 100, 100, 72, 180, "Inter-SemiBold.otf", 11, PAPER, tracking=2.2, flip=False)
    # top text must read left-to-right across the top: start at 180° (left) and go clockwise... SVG angles increase clockwise, so start at ~195 and move +; compute width to centre
    _, tw = arc_text("TRUST THE LAST RELEASE", 100, 100, 72, 0, "Inter-SemiBold.otf", 11, PAPER, tracking=2.2)
    span = (tw/72)*(180/math.pi); top, _ = arc_text("TRUST THE LAST RELEASE", 100, 100, 72, 270 - span/2, "Inter-SemiBold.otf", 11, PAPER, tracking=2.2)
    _, bw = arc_text("CHECK THE NEXT", 100, 100, 72, 0, "Inter-SemiBold.otf", 11, PAPER, tracking=2.2)
    span2 = (bw/72)*(180/math.pi); bot, _ = arc_text("CHECK THE NEXT", 100, 100, 72, 90 + span2/2, "Inter-SemiBold.otf", 11, PAPER, tracking=2.2, flip=True)
    b += top + bot
    for a in (175, 5): x, y = P(100, 100, 72, a); b += poly(hexpts(x, y, 3.2), AMBER)
    return svg(200, 200, b)
def sticker_hex():
    b = f'<rect width="200" height="200" fill="#E9E9E9"/>'
    b += poly(hexpts(100, 100, 96), INK) + poly(hexpts(100, 100, 90), "none", f'stroke="{G3}" stroke-width="1.2"')
    b += mark(body=G3, window=INK, seed=G3, tell=AMBER, tx=68, ty=36, s=0.64)
    wm, ww = wordmark(0, 0, 20, PAPER, G3); wm, _ = wordmark(100 - ww/2, 134, 20, PAPER, G3); b += wm
    b += T("garnet-guard.dev", TEXT, 7, 100 - TW("garnet-guard.dev", TEXT, 7)/2, 152, "#A9AFB7")
    return svg(200, 200, b)
def sticker_laptop():
    b = f'<rect width="260" height="110" fill="#E9E9E9"/>'
    b += f'<rect x="10" y="20" width="240" height="70" rx="10" fill="{PAPER}" stroke="{G7}" stroke-width="2"/>'
    b += mark(body=G7, window=PAPER, seed=G9, tx=22, ty=28, s=0.54)
    b += T("deps checked by", TEXT_MED, 11, 86, 50, SLATE)
    wm, _ = wordmark(86, 76, 24, INK, G7); b += wm
    return svg(260, 110, b)
def sticker_tell():
    b = f'<rect width="120" height="120" fill="#E9E9E9"/>' + aril(60, 56, 40, 3, fill=AMBER)
    b += T("the tell", "Inter-SemiBold.otf", 12, 60 - TW("the tell", "Inter-SemiBold.otf", 12)/2, 62, G9)
    b += T("one seed that differs", TEXT, 5.5, 60 - TW("one seed that differs", TEXT, 5.5)/2, 108, SLATE)
    return svg(120, 120, b)
def sticker_quiet():
    b = f'<rect width="300" height="90" fill="#E9E9E9"/>' + f'<rect x="10" y="10" width="280" height="70" rx="35" fill="{INK}"/>'
    b += mark(body=G3, window=INK, seed=G3, tell=AMBER, tx=24, ty=18, s=0.54)
    b += T("nothing worth a look", "Inter-SemiBold.otf", 17, 88, 44, PAPER) + T("quiet on clean updates", TEXT, 10, 88, 62, "#A9AFB7")
    return svg(300, 90, b)
def sticker_diff():
    b = f'<rect width="200" height="200" fill="#E9E9E9"/>' + circ(100, 100, 92, PAPER) + circ(100, 100, 92, "none", f'stroke="{G1}" stroke-width="3"')
    b += poly([(100, 50), (150, 136), (50, 136)], G7) + "".join(poly(hexpts(x, y, 9), AMBER if i == 2 else PAPER) for i, (x, y) in enumerate(((100, 92), (84, 118), (116, 118))))
    b += T("I read the diff", "Inter-SemiBold.otf", 13, 100 - TW("I read the diff", "Inter-SemiBold.otf", 13)/2, 166, INK)
    return svg(200, 200, b)
for n, fn in (("round-badge", sticker_round), ("hex-laptop", sticker_hex), ("checked-by", sticker_laptop), ("the-tell", sticker_tell), ("quiet", sticker_quiet), ("i-read-the-diff", sticker_diff)):
    W(f"explore/sticker-{n}.svg", svg(1, 1, "") if False else fn())

# lockup ideas
def lockup_badge_circle():
    b = circ(60, 60, 56, G7) + mark(body=PAPER, window=G7, seed=PAPER, tell=AMBER, tx=30, ty=22, s=0.6)
    _, tw = arc_text("GARNET GUARD", 60, 60, 44, 0, "Inter-SemiBold.otf", 9.5, PAPER, tracking=2)
    span = (tw/44)*(180/math.pi); t, _ = arc_text("GARNET GUARD", 60, 60, 44, 90 + span/2, "Inter-SemiBold.otf", 9.5, PAPER, tracking=2, flip=True)
    return svg(120, 120, b + t)
def lockup_seed_tittle():
    # wordmark where the i-less name gets a seed: the tell replaces the period in "garnet guard."
    wm, ww = wordmark(4, 56, 56, INK, G7)
    return svg(round(ww)+40, 72, wm + poly(hexpts(ww + 18, 50, 7), AMBER))
def lockup_vertical_rule():
    wm, ww = wordmark(0, 0, 36, INK, G7)
    b = mark(body=G7, window="none", seed=G9, tx=0, ty=0, s=0.9) + f'<path d="M104,14 V86" stroke="{G1}" stroke-width="2"/>'
    wm, _ = wordmark(120, 52, 36, INK, G7); b += wm + T("A second reviewer for every dependency update.", TEXT, 11, 121, 74, SLATE)
    return svg(round(120+ww)+80, 100, b)
W("explore/lockup-circle-badge.svg", lockup_badge_circle())
W("explore/lockup-seed-full-stop.svg", lockup_seed_tittle())
W("explore/lockup-with-one-liner.svg", lockup_vertical_rule())
print("explore done")

# ---------- plated lockup: reads on any background (README fallback) ----------
def lockup_plate(pad_x=18, pad_y=10, rx=14, fill=PAPER, edge=None):
    size = 56; mk = 0.9
    wm, ww = wordmark(112 + pad_x, 76 + pad_y, size, INK, G7)
    total = 112 + ww + 10 + 2*pad_x; h = 100 + 2*pad_y
    stroke = f' stroke="{edge}" stroke-width="1"' if edge else ""
    plate = f'<rect x="0.5" y="0.5" width="{total-1:.0f}" height="{h-1}" rx="{rx}" fill="{fill}"{stroke}/>'
    return svg(round(total), h, plate + mark(G7, "none", G9, AMBER, tx=4+pad_x, ty=6+pad_y, s=mk) + wm, vb=f"0 0 {total:.0f} {h}")
W("kit/lockup/lockup-horizontal-plate.svg", lockup_plate())
