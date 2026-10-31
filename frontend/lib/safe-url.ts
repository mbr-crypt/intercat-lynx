/**
 * Links that come from outside (RSS feeds, CVE references, advisories) are data,
 * not code. A `javascript:` or `data:` URL in an `href` runs script in this
 * site's origin when clicked, so only plain http(s) addresses become links.
 */
export function safeHttpUrl(value: string | null | undefined): string | undefined {
  if (!value) return undefined;
  try {
    const url = new URL(value.trim());
    return url.protocol === "http:" || url.protocol === "https:" ? url.href : undefined;
  } catch {
    return undefined;
  }
}
