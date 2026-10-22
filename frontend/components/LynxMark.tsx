import type { SVGProps } from "react";

/**
 * InterCat Lynx logo mark: a solid, angular lynx mask. Eyes, nose and the
 * scan slit are cut out of the shape (even-odd fill), so it is a single colour
 * and follows the text colour of its surroundings (`currentColor`). It works
 * in the light and the dark theme.
 *
 * - variant "mask":    the head alone. For small sizes (navigation, favicon).
 * - variant "reticle": the head inside a broken ring with four tick marks.
 *                      Main logo for large display (About page, hero).
 *
 * Same geometry as docs/assets/logo/build_logo.py, which generates the logo files.
 */

const HEAD =
  "M256 128 L212 136 L192 52 L180 -10 L170 66 L126 152 L100 196 L94 238 L64 272 L98 264 L74 326 L108 308 L92 388 L142 350 L188 396 L232 414 L256 420 L280 414 L324 396 L370 350 L420 388 L404 308 L438 326 L414 264 L448 272 L418 238 L412 196 L386 152 L342 66 L332 -10 L320 52 L300 136 L256 128 Z M146 206 L240 222 L236 236 L196 246 L158 228 Z M366 206 L272 222 L276 236 L316 246 L354 228 Z M232 272 L280 272 L256 302 Z M250 142 L262 142 L262 196 L250 196 Z";

const TICKS = "M256 -66 V-30 M256 458 V494 M-24 214 H12 M500 214 H536";

export function LynxMark({
  variant = "mask",
  ...props
}: { variant?: "mask" | "reticle" } & SVGProps<SVGSVGElement>) {
  const reticle = variant === "reticle";
  return (
    <svg
      viewBox={reticle ? "-40 -80 592 592" : "40 -24 432 460"}
      role="img"
      aria-label="InterCat Lynx"
      {...props}
    >
      {reticle && (
        <g fill="none" stroke="currentColor" strokeWidth={5}>
          <circle
            cx={256}
            cy={214}
            r={262}
            strokeDasharray="150 28 150 28 150 28 150 28"
            transform="rotate(-80 256 214)"
          />
          <path d={TICKS} />
        </g>
      )}
      <path fill="currentColor" fillRule="evenodd" d={HEAD} />
    </svg>
  );
}
