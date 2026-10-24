/**
 * Accent colour of an instance (Administration > Einstellungen > Darstellung).
 *
 * The page uses the Tailwind scale `blue` for everything that is "brand colour"
 * (buttons, links, active tabs). The steps 400 to 700 and the CSS variables
 * --primary, --ring and --link are replaced by shades of the chosen colour.
 * The light tints (50 to 300) and the dark ones (800, 900) stay as they are.
 *
 * Only a strictly checked #rrggbb value is turned into CSS, nothing else.
 */

const HEX = /^#[0-9a-f]{6}$/i;

type RGB = [number, number, number];

function parse(hex: string): RGB {
  return [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16)) as RGB;
}

function mix(a: RGB, b: RGB, amount: number): RGB {
  return a.map((v, i) => Math.round(v + (b[i] - v) * amount)) as RGB;
}

function toHsl([r, g, b]: RGB): string {
  const rn = r / 255, gn = g / 255, bn = b / 255;
  const max = Math.max(rn, gn, bn), min = Math.min(rn, gn, bn);
  const l = (max + min) / 2;
  const d = max - min;
  let h = 0, s = 0;
  if (d !== 0) {
    s = d / (1 - Math.abs(2 * l - 1));
    if (max === rn) h = ((gn - bn) / d) % 6;
    else if (max === gn) h = (bn - rn) / d + 2;
    else h = (rn - gn) / d + 4;
    h = Math.round(h * 60);
    if (h < 0) h += 360;
  }
  return `${h} ${Math.round(s * 100)}% ${Math.round(l * 100)}%`;
}

const channels = (c: RGB) => c.join(" ");
const WHITE: RGB = [255, 255, 255];
const BLACK: RGB = [0, 0, 0];

/** CSS that applies the accent colour, or "" if the value is not a valid colour. */
export function accentCss(accent: string | null | undefined): string {
  if (!accent || !HEX.test(accent)) return "";
  const base = parse(accent);
  const c600 = base;
  const c700 = mix(base, BLACK, 0.15);
  const c500 = mix(base, WHITE, 0.2);
  const c400 = mix(base, WHITE, 0.55); // readable as text on the dark background
  return (
    `html:root{--blue-400:${channels(c400)};--blue-500:${channels(c500)};--blue-600:${channels(c600)};` +
    `--blue-700:${channels(c700)};--primary:${toHsl(c600)};--ring:${toHsl(c600)};--link:${toHsl(c600)}}` +
    `html.dark{--ring:${toHsl(c400)};--link:${toHsl(c400)}}`
  );
}
