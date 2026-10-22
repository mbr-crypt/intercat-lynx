"""Erzeugt die Lynx-Logodateien (SVG) aus einer einzigen Geometrie.
Linienkunst-Bildmarke, fette Icon-Variante, Lockups mit Wortmarke (Text als Pfade, keine Schrift nötig)."""
import os
from fontTools.ttLib import TTFont
from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "out")
os.makedirs(OUT, exist_ok=True)

# ---- Geometrie der linken Kopfhälfte (viewBox 512 x ~420), rechts gespiegelt ----
HALF_LINE = [
    # Kontur: Stirn, Ohr, Wange, Backenbart, Kinn
    "M256 124 Q232 122 210 132 L188 56 L126 154 Q100 192 94 226 L72 270 L100 264 L80 322 L110 306 L98 376 L140 344 Q176 388 214 398 Q238 406 256 406",
    # Auge, Braue, Augenlinie
    "M160 212 Q196 186 238 216 Q198 240 160 212 Z",
    "M152 192 Q196 162 244 194",
    "M156 205 Q138 203 124 215",
    # Stirnzeichnung
    "M240 138 L244 168 M224 142 L228 164",
]
CENTER_LINE = [
    "M232 268 Q256 256 280 268 L256 296 Z",           # Nase
    "M256 152 L256 256 M256 296 L256 314 Q240 338 212 328 M256 314 Q272 338 300 328",  # Rücken, Mund
]
TUFT = "M194 62 L180 2 L174 66 Z"
PUPIL = (203, 214, 6, 12)  # cx, cy, rx, ry

# fette Variante für kleine Größen: weniger Details, dickere Linie
HALF_BOLD = [
    "M256 124 Q232 122 210 132 L188 56 L126 154 Q100 192 94 226 L72 270 L100 264 L80 322 L110 306 L98 376 L140 344 Q176 388 214 398 Q238 406 256 406",
    "M154 206 Q196 188 238 224 Q190 238 154 206 Z",   # Auge, gefüllt
]
CENTER_BOLD = ["M232 268 Q256 256 280 268 L256 296 Z"]

def line_svg(color, stroke=7, bg=None, pad=48, extra_defs=""):
    w, h = 512, 410 + 2 * 0
    vb = f"{-pad} {-pad+0} {512+2*pad} {420+2*pad}"
    parts = []
    if bg:
        parts.append(f'<rect x="{-pad}" y="{-pad}" width="{512+2*pad}" height="{420+2*pad}" fill="{bg}"/>')
    parts.append(f'<g fill="none" stroke="{color}" stroke-width="{stroke}" stroke-linecap="round" stroke-linejoin="round">')
    parts.append('<g id="h">' + "".join(f'<path d="{d}"/>' for d in HALF_LINE) + '</g>')
    parts.append('<use href="#h" transform="translate(512 0) scale(-1 1)"/>')
    parts += [f'<path d="{d}"/>' for d in CENTER_LINE]
    parts.append('</g>')
    parts.append(f'<g fill="{color}"><path id="t" d="{TUFT}"/><use href="#t" transform="translate(512 0) scale(-1 1)"/>'
                 f'<ellipse cx="{PUPIL[0]}" cy="{PUPIL[1]}" rx="{PUPIL[2]}" ry="{PUPIL[3]}"/>'
                 f'<ellipse cx="{512-PUPIL[0]}" cy="{PUPIL[1]}" rx="{PUPIL[2]}" ry="{PUPIL[3]}"/></g>')
    return vb, "".join(parts)

def bold_svg(color, stroke=18, bg=None, pad=40):
    vb = f"{-pad} {-pad} {512+2*pad} {420+2*pad}"
    parts = []
    if bg:
        parts.append(f'<rect x="{-pad}" y="{-pad}" width="{512+2*pad}" height="{420+2*pad}" fill="{bg}"/>')
    parts.append(f'<g fill="none" stroke="{color}" stroke-width="{stroke}" stroke-linecap="round" stroke-linejoin="round">')
    parts.append('<g id="h" fill="%s">' % color + "".join(f'<path d="{d}"' + (' fill="none"' if d.startswith('M256') else '') + '/>' for d in HALF_BOLD) + '</g>')
    parts.append('<use href="#h" transform="translate(512 0) scale(-1 1)"/>')
    parts += [f'<path d="{d}"/>' for d in CENTER_BOLD]
    parts.append('</g>')
    parts.append(f'<g fill="{color}"><path id="t" d="M198 66 L180 -6 L170 70 Z"/><use href="#t" transform="translate(512 0) scale(-1 1)"/></g>')
    return vb, "".join(parts)

def write(name, vb, body, size=None):
    x, y, w, h = [float(v) for v in vb.split()]
    sz = f' width="{int(w)}" height="{int(h)}"' if size is None else f' width="{size[0]}" height="{size[1]}"'
    svg = f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{vb}"{sz}>{body}</svg>\n'
    open(os.path.join(OUT, name), "w").write(svg)

# ---- Text als Pfade ----
FONT = TTFont("/usr/share/fonts/truetype/crosextra/Carlito-Regular.ttf")
GS = FONT.getGlyphSet(); CMAP = FONT.getBestCmap(); UPM = FONT["head"].unitsPerEm

def text_path(text, size, tracking, x=0, y=0, anchor="start"):
    scale = size / UPM
    adv = []
    for ch in text:
        g = CMAP[ord(ch)]; adv.append(GS[g].width * scale)
    total = sum(adv) + tracking * (len(text) - 1)
    cx = x - total / 2 if anchor == "middle" else x
    d = []
    for ch, a in zip(text, adv):
        pen = SVGPathPen(GS)
        tp = TransformPen(pen, (scale, 0, 0, -scale, cx, y))
        GS[CMAP[ord(ch)]].draw(tp)
        d.append(pen.getCommands())
        cx += a + tracking
    return " ".join(d), total

if __name__ == "__main__":
    for col, tag in (("#ffffff", "weiss"), ("#000000", "schwarz")):
        vb, body = line_svg(col)
        write(f"lynx-bildmarke-{tag}.svg", vb, body)
        vb, body = bold_svg(col)
        write(f"lynx-icon-fett-{tag}.svg", vb, body)
    # Lockup stehend: Kopf, darunter Wortmarke
    for col, tag in (("#ffffff", "weiss"), ("#000000", "schwarz")):
        vb, body = line_svg(col)
        d, tw = text_path("INTERCAT LYNX", 60, 22, x=256, y=420 + 100, anchor="middle")
        half = max(tw / 2, 256) + 56
        vb2 = f"{256-half} -48 {2*half} {420+48+160}"
        write(f"lynx-logo-{tag}.svg", vb2, body + f'<path d="{d}" fill="{col}"/>')
    # Vorschau auf Markenhintergrund
    vb, body = line_svg("#ffffff", bg="#131416")
    write("preview-bildmarke.svg", vb, body)
    vb, body = bold_svg("#ffffff", bg="#131416")
    write("preview-icon.svg", vb, body)
    print(os.listdir(OUT))

def app_icon(path, bg="#131416", fg="#ffffff", radius=104):
    """Quadratisches App-Icon/Favicon: fette Bildmarke weiß auf Markenhintergrund."""
    vb, body = bold_svg(fg, pad=0)
    # body enthält <g>-Gruppen in 512er-Koordinaten; mittig skalieren
    svg = (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" width="512" height="512">'
           f'<rect width="512" height="512" rx="{radius}" fill="{bg}"/>'
           f'<g transform="translate(256 262) scale(0.84) translate(-256 -203)">{body}</g></svg>\n')
    open(path, "w").write(svg)

app_icon(os.path.join(OUT, "lynx-appicon.svg"))
