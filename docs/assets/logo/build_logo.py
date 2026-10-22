"""InterCat Lynx logo files, generated from one geometry.

Run:  python3 build_logo.py          (SVG files, needs fonttools and the Carlito fonts)
      python3 build_logo.py --png    (also PNG and favicon.ico, needs playwright + Pillow + chromium)

Design: a solid, angular lynx mask (straight lines only). Eyes, nose and the
scan slit are cut out of the shape (even-odd fill), so the mark is one colour
and works on any background. Two forms:

  mask     the head alone. For small sizes (navigation, favicon, app icon).
  reticle  the head inside a broken ring with four tick marks (targeting reticle).
           Main logo for large display.

Only white and black versions exist (Intercat style guide). The text in the
lockup is converted to outlines, so no font is needed to display the files.
"""
import os, re, sys
from fontTools.ttLib import TTFont
from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen

HERE = os.path.dirname(os.path.abspath(__file__))
FONTS = "/usr/share/fonts/truetype/crosextra"   # Carlito, metric clone of Calibri

# ---- Geometry: left half of the head from the forehead down, mirrored to the right ----
LEFT = [(256, 128), (212, 136), (192, 52), (180, -10), (170, 66), (126, 152), (100, 196), (94, 238),
        (64, 272), (98, 264), (74, 326), (108, 308), (92, 388), (142, 350), (188, 396), (232, 414)]
CHIN = (256, 420)
EYE_L = [(146, 206), (240, 222), (236, 236), (196, 246), (158, 228)]
NOSE = [(232, 272), (280, 272), (256, 302)]
SLIT = [(250, 142), (262, 142), (262, 196), (250, 196)]
RETICLE = dict(cx=256, cy=214, r=262, tick=18, stroke=5, dash="150 28 150 28 150 28 150 28", rot=-80)

def mirror(p): return (512 - p[0], p[1])
OUTLINE = LEFT + [CHIN] + [mirror(p) for p in reversed(LEFT)][0:]
def poly(pts): return "M" + " L".join(f"{x} {y}" for x, y in pts) + " Z"
HEAD_D = " ".join([poly(OUTLINE), poly(EYE_L), poly([mirror(p) for p in EYE_L]), poly(NOSE), poly(SLIT)])

def ticks_d():
    c, r, t = RETICLE["cx"], RETICLE["r"], RETICLE["tick"]; cx, cy = RETICLE["cx"], RETICLE["cy"]
    return (f"M{cx} {cy-r-t} V{cy-r+t} M{cx} {cy+r-t} V{cy+r+t} "
            f"M{cx-r-t} {cy} H{cx-r+t} M{cx+r-t} {cy} H{cx+r+t}")

def ring_svg(color):
    R = RETICLE
    return (f'<g fill="none" stroke="{color}" stroke-width="{R["stroke"]}">'
            f'<circle cx="{R["cx"]}" cy="{R["cy"]}" r="{R["r"]}" stroke-dasharray="{R["dash"]}" '
            f'transform="rotate({R["rot"]} {R["cx"]} {R["cy"]})"/><path d="{ticks_d()}"/></g>')

def head_svg(color): return f'<path fill="{color}" fill-rule="evenodd" d="{HEAD_D}"/>'

VB_MASK = (40, -24, 432, 460)
VB_RETICLE = (-40, -80, 592, 592)

def svg(vb, body, bg=None, rx=0):
    x, y, w, h = vb
    r = f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}" fill="{bg}"/>' if bg else ""
    return f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{x} {y} {w} {h}" width="{w}" height="{h}">{r}{body}</svg>\n'

# ---- Text as outlines ----
_fonts = {}
def _font(name):
    if name not in _fonts:
        f = TTFont(os.path.join(FONTS, name)); _fonts[name] = (f, f.getGlyphSet(), f.getBestCmap(), f["head"].unitsPerEm)
    return _fonts[name]

def text_width(text, font, size, tracking):
    f, gs, cmap, upm = _font(font)
    return sum(gs[cmap[ord(c)]].width * size / upm for c in text) + tracking * (len(text) - 1)

def text_path(text, font, size, tracking, x, y):
    f, gs, cmap, upm = _font(font); s = size / upm; d = []
    for c in text:
        pen = SVGPathPen(gs); gs[cmap[ord(c)]].draw(TransformPen(pen, (s, 0, 0, -s, x, y)))
        d.append(pen.getCommands()); x += gs[cmap[ord(c)]].width * s + tracking
    return " ".join(d)

def lockup(color):
    size, track, gap = 78, 26, 58
    w1 = text_width("INTERCAT", "Carlito-Regular.ttf", size, track)
    w2 = text_width("LYNX", "Carlito-Bold.ttf", size, track)
    total = w1 + gap + w2
    x0 = 256 - total / 2; base = 512 + 118
    d = (text_path("INTERCAT", "Carlito-Regular.ttf", size, track, x0, base) + " " +
         text_path("LYNX", "Carlito-Bold.ttf", size, track, x0 + w1 + gap, base))
    half = max(total / 2, 296) + 40
    vb = (256 - half, -80, 2 * half, base + 80 + 40)
    return svg(vb, ring_svg(color) + head_svg(color) + f'<path fill="{color}" d="{d}"/>')

def build():
    out = {}
    for tag, col in (("weiss", "#ffffff"), ("schwarz", "#000000")):
        out[f"lynx-maske-{tag}.svg"] = svg(VB_MASK, head_svg(col))
        out[f"lynx-bildmarke-{tag}.svg"] = svg(VB_RETICLE, ring_svg(col) + head_svg(col))
        out[f"lynx-logo-{tag}.svg"] = lockup(col)
    # quadratisches App-Icon: Maske weiß auf Markenhintergrund
    out["lynx-appicon.svg"] = (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" width="512" height="512">'
        '<rect width="512" height="512" rx="104" fill="#131416"/>'
        f'<g transform="translate(256 262) scale(0.74) translate(-256 -205)">{head_svg("#ffffff")}</g></svg>\n')
    for name, content in out.items():
        open(os.path.join(HERE, name), "w").write(content)
    return list(out)

def build_png():
    from playwright.sync_api import sync_playwright
    from PIL import Image
    def render(svgname, outname, width):
        s = open(os.path.join(HERE, svgname)).read()
        w, h = [float(v) for v in re.search(r'viewBox="([^"]+)"', s).group(1).split()[2:]]
        H = round(width * h / w)
        hp = os.path.join(HERE, "_t.html")
        open(hp, "w").write(f'<html><body style="margin:0;background:transparent"><img src="file://{HERE}/{svgname}" style="width:{width}px;height:{H}px;display:block"></body></html>')
        with sync_playwright() as p:
            b = p.chromium.launch(executable_path="/opt/pw-browsers/chromium", args=["--allow-file-access-from-files"])
            pg = b.new_page(viewport={"width": width, "height": H}); pg.goto("file://" + hp)
            pg.screenshot(path=os.path.join(HERE, outname), omit_background=True); b.close()
        os.remove(hp)
    for tag in ("weiss", "schwarz"):
        render(f"lynx-bildmarke-{tag}.svg", f"lynx-bildmarke-{tag}.png", 2000)
        render(f"lynx-logo-{tag}.svg", f"lynx-logo-{tag}.png", 2000)
        render(f"lynx-maske-{tag}.png".replace(".png", ".svg"), f"lynx-maske-{tag}.png", 1000)
    render("lynx-appicon.svg", "apple-icon.png", 180)
    tmp = []
    for n in (16, 32, 48):
        render("lynx-appicon.svg", f"_f{n}.png", n); tmp.append(f"_f{n}.png")
    ims = [Image.open(os.path.join(HERE, t)).convert("RGBA") for t in tmp]
    ims[2].save(os.path.join(HERE, "favicon.ico"), sizes=[(16, 16), (32, 32), (48, 48)], append_images=ims[:2])
    for t in tmp: os.remove(os.path.join(HERE, t))

if __name__ == "__main__":
    print(build())
    if "--png" in sys.argv: build_png()
