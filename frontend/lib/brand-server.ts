/**
 * Branding of the instance, read on the server (layout, page title).
 *
 * The backend answers /api/v1/branding without login. The web server asks for it
 * while it draws a page, so a changed name, colour or logo is there from the first
 * paint (no flash of the old look).
 *
 * The answer is kept in memory for a few seconds, so a busy site does not ask the
 * backend for every page (the backend has a request limit per address, and all pages
 * come from the web server's address). If the backend does not answer, the last known
 * branding stays in use; only before the first answer the default look is shown.
 */

import { connection } from "next/server";
import { apiBase } from "./config";
import { PRODUCT_NAME } from "./branding";
import { DEFAULT_BRAND, type Brand } from "./brand";

const TTL_MS = 5000;
let cached: { at: number; brand: Brand } | null = null;
let inflight: Promise<Brand> | null = null;

async function load(): Promise<Brand> {
  const response = await fetch(`${apiBase()}/api/v1/branding`, {
    cache: "no-store",
    signal: AbortSignal.timeout(2000),
  });
  if (!response.ok) throw new Error(`branding ${response.status}`);
  const data = await response.json();
  return {
    name: typeof data.name === "string" && data.name ? data.name : PRODUCT_NAME,
    accent: typeof data.accent === "string" ? data.accent : null,
    footer_text: typeof data.footer_text === "string" ? data.footer_text : null,
    url: typeof data.url === "string" ? data.url : null,
    logo_light: typeof data.logo_light === "string" ? data.logo_light : null,
    logo_dark: typeof data.logo_dark === "string" ? data.logo_dark : null,
    custom: data.custom === true,
  };
}

export async function getBrand(): Promise<Brand> {
  // The branding can change at any time: draw pages when they are asked for, never at build time
  await connection();
  const now = Date.now();
  if (cached && now - cached.at < TTL_MS) return cached.brand;
  // Several pages drawn at the same moment share one request
  inflight ??= load()
    .then((brand) => {
      cached = { at: Date.now(), brand };
      return brand;
    })
    .catch(() => {
      // Keep the last known look (or the default); try again in a few seconds
      cached = { at: Date.now(), brand: cached?.brand ?? DEFAULT_BRAND };
      return cached.brand;
    })
    .finally(() => {
      inflight = null;
    });
  return inflight;
}
