/** Calls to the product selection API (/api/v1/watchlist) with the bearer token. */

export interface Watch {
  id: number;
  vendor: string;
  product: string | null;
  label: string;
  created_at: string;
  cves_7d: number;
  cves_30d: number;
}

export interface CatalogVendor {
  vendor: string;
  label: string;
  product_count: number;
  watched: boolean;
}

export interface CatalogProduct {
  vendor: string;
  product: string;
  label: string;
  cve_count: number;
  watched: boolean;
}

export interface CatalogResult {
  vendors: CatalogVendor[];
  products: CatalogProduct[];
  catalog_size: number;
}

export interface FeedItem {
  cve_id: string;
  title: string;
  severity: string | null;
  cvss_score: number | null;
  published_at: string | null;
  exploited_in_the_wild: boolean;
  products: string[];
}

export interface FeedPage {
  total: number;
  page: number;
  page_size: number;
  items: FeedItem[];
}

export interface WindowSummary {
  new: number;
  critical: number;
  high: number;
  exploited: number;
}

export interface WatchSummary {
  watch_count: number;
  last_24h: WindowSummary;
  last_7d: WindowSummary;
}

function messageOf(body: any, fallback: string): string {
  const detail = body?.detail;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail) && detail.length > 0) {
    return detail
      .map((d) => (typeof d?.msg === "string" ? d.msg.replace(/^Value error, /, "") : ""))
      .filter(Boolean)
      .join(" ");
  }
  return fallback;
}

export interface NotificationSettings {
  in_app_enabled: boolean;
  email_enabled: boolean;
  email_address: string;
  smtp_configured: boolean;
  webhook_enabled: boolean;
  webhook_url: string | null;
  webhook_has_secret: boolean;
  min_severity: string;
  always_exploited: boolean;
  last_email_ok_at: string | null;
  last_email_error: string | null;
  last_webhook_ok_at: string | null;
  last_webhook_error: string | null;
  /** only present in the answer that created or renewed the secret */
  new_webhook_secret: string | null;
}

export type NotificationSettingsPatch = Partial<
  Pick<
    NotificationSettings,
    "in_app_enabled" | "email_enabled" | "webhook_enabled" | "webhook_url" | "min_severity" | "always_exploited"
  >
>;

export function watchFetch<T>(
  token: string,
  path: string,
  init: { method?: string; body?: unknown } = {}
): Promise<T> {
  return apiFetch<T>(token, `/api/v1/watchlist${path}`, init);
}

export function notifyFetch<T>(
  token: string,
  path: string,
  init: { method?: string; body?: unknown } = {}
): Promise<T> {
  return apiFetch<T>(token, `/api/v1/notification-settings${path}`, init);
}

async function apiFetch<T>(
  token: string,
  url: string,
  init: { method?: string; body?: unknown } = {}
): Promise<T> {
  const response = await fetch(url, {
    method: init.method ?? "GET",
    headers: {
      Authorization: `Bearer ${token}`,
      ...(init.body !== undefined ? { "Content-Type": "application/json" } : {}),
    },
    body: init.body !== undefined ? JSON.stringify(init.body) : undefined,
  });
  if (response.status === 204) return undefined as T;
  const body = await response.json().catch(() => null);
  if (!response.ok) {
    throw new Error(messageOf(body, `Fehler ${response.status}`));
  }
  return body as T;
}
