/** BSI CERT-Bund warnings (/api/v1/bsi). Reading is public, switch and fetch are admin only. */

import { ApiError } from "@/lib/admin-api";
import { authFetch } from "@/lib/authed-fetch";

export interface BsiAdvisory {
  advisory_id: string;
  title: string;
  severity: "kritisch" | "hoch" | "mittel" | "niedrig" | null;
  published_at: string | null;
  updated_at: string | null;
  url: string;
  products: string[];
  cve_count: number;
  cves: string[];
}

export interface BsiPage {
  items: BsiAdvisory[];
  total: number;
  page: number;
  page_size: number;
  source: string;
}

export interface BsiStatus {
  enabled: boolean;
  last_sync: string | null;
  advisories: number;
  feed: string;
}

export const BSI_SEVERITIES = ["kritisch", "hoch", "mittel", "niedrig"] as const;

export const BSI_SEVERITY_CLASS: Record<string, string> = {
  kritisch: "bg-red-100 text-red-800 border-red-300 dark:bg-red-900/30 dark:text-red-400 dark:border-red-700",
  hoch: "bg-orange-100 text-orange-800 border-orange-300 dark:bg-orange-900/30 dark:text-orange-400 dark:border-orange-700",
  mittel: "bg-yellow-100 text-yellow-800 border-yellow-300 dark:bg-yellow-900/30 dark:text-yellow-400 dark:border-yellow-700",
  niedrig: "bg-gray-100 text-gray-700 border-gray-300 dark:bg-gray-700/40 dark:text-gray-300 dark:border-gray-600",
};

export const BSI_SOURCE_NOTE =
  "Quelle: Bundesamt für Sicherheit in der Informationstechnik (BSI), CERT-Bund, Warn- und Informationsdienst. " +
  "Hier stehen nur Nummer, Titel, Einstufung und Verweise; der Text der Meldung steht beim BSI. " +
  "Diese Seite ist kein Angebot des BSI und steht in keiner Verbindung zu ihm.";

export async function fetchBsiPage(
  params: { page: number; severity?: string; q?: string },
  signal?: AbortSignal
): Promise<BsiPage> {
  const query = new URLSearchParams({ page: String(params.page), page_size: "25" });
  if (params.severity) query.set("severity", params.severity);
  if (params.q) query.set("q", params.q);
  const response = await authFetch(`/api/v1/bsi/advisories?${query}`, { signal });
  if (!response.ok) throw new ApiError(`Fehler ${response.status}`, response.status);
  return response.json();
}

export async function bsiAdminFetch<T>(
  token: string,
  path: string,
  init: { method?: string; body?: unknown } = {}
): Promise<T> {
  const response = await fetch(`/api/v1/bsi${path}`, {
    method: init.method ?? "GET",
    headers: {
      Authorization: `Bearer ${token}`,
      ...(init.body !== undefined ? { "Content-Type": "application/json" } : {}),
    },
    body: init.body !== undefined ? JSON.stringify(init.body) : undefined,
  });
  const body = await response.json().catch(() => null);
  if (!response.ok) {
    const detail = typeof body?.detail === "string" ? body.detail : `Fehler ${response.status}`;
    throw new ApiError(detail, response.status);
  }
  return body as T;
}
