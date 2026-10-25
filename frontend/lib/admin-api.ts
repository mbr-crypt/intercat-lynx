/** Calls to the admin API (/api/v1/admin/...) with the bearer token. */

export type Role = "admin" | "analyst" | "viewer";

export interface AdminUser {
  id: number;
  username: string;
  email: string;
  full_name: string | null;
  role: Role;
  is_active: boolean;
  is_verified: boolean;
  is_locked: boolean;
  totp_enabled: boolean;
  must_change_password: boolean;
  created_at: string;
  last_login_at: string | null;
  failed_login_attempts: number;
}

export interface Paged<T> {
  total: number;
  page: number;
  page_size: number;
  items: T[];
}

export interface AuditEvent {
  id: number;
  created_at: string;
  actor_username: string | null;
  action: string;
  target_username: string | null;
  detail: string | null;
}

export interface UserWithPassword {
  user: AdminUser;
  temporary_password: string | null;
}

/** FastAPI answers with a string or, for validation errors, a list of objects. */
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

/** An error answer of the API with its HTTP status (429 = too many requests). */
export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly retryAfter?: number
  ) {
    super(message);
  }
}

export async function adminFetch<T>(
  token: string,
  path: string,
  init: { method?: string; body?: unknown } = {}
): Promise<T> {
  const response = await fetch(`/api/v1/admin${path}`, {
    method: init.method ?? "GET",
    headers: {
      Authorization: `Bearer ${token}`,
      ...(init.body !== undefined ? { "Content-Type": "application/json" } : {}),
    },
    body: init.body !== undefined ? JSON.stringify(init.body) : undefined,
  });
  const body = await response.json().catch(() => null);
  if (!response.ok) {
    const retryAfter = Number(response.headers.get("Retry-After")) || undefined;
    throw new ApiError(messageOf(body, `Fehler ${response.status}`), response.status, retryAfter);
  }
  return body as T;
}

/** Reset 2FA lives with the other 2FA endpoints. */
export async function resetTwoFactor(token: string, userId: number): Promise<void> {
  const response = await fetch(`/api/v1/auth/users/${userId}/reset-2fa`, {
    method: "PUT",
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!response.ok) {
    const body = await response.json().catch(() => null);
    throw new Error(messageOf(body, `Fehler ${response.status}`));
  }
}

export const ROLE_LABEL: Record<Role, string> = {
  admin: "Administrator",
  analyst: "Analyst",
  viewer: "Betrachter",
};

export const ROLE_HELP: Record<Role, string> = {
  admin: "Alles, inklusive Administration",
  analyst: "Lesen und Inhalte bearbeiten",
  viewer: "Nur lesen",
};

export const AUDIT_LABEL: Record<string, string> = {
  "user.created": "Benutzer angelegt",
  "user.updated": "Benutzerdaten geändert",
  "user.role_changed": "Rolle geändert",
  "user.activated": "Benutzer aktiviert",
  "user.deactivated": "Benutzer deaktiviert",
  "user.unlocked": "Sperre aufgehoben",
  "user.deleted": "Benutzer gelöscht",
  "user.password_reset": "Passwort zurückgesetzt",
  "user.2fa_reset": "2FA zurückgesetzt",
  "user.sessions_revoked": "Überall abgemeldet",
  "setting.registration": "Registrierung umgestellt",
  "import.started": "Datenimport gestartet",
  "setting.smtp": "E-Mail-Server geändert",
  "setting.smtp_test": "Testmail gesendet",
  "setting.nvd_key": "NVD-Schlüssel geändert",
  "setting.public_url": "Öffentliche Adresse geändert",
  "setting.branding": "Darstellung geändert",
};

export function formatDate(value: string | null): string {
  if (!value) return "nie";
  return new Date(value).toLocaleString("de-DE", { dateStyle: "short", timeStyle: "short" });
}

/** Background activity (what the system does right now), see GET /admin/activity. */
export interface ActivityLogEntry {
  t: string;
  text: string;
}

export interface ImportStatus {
  state: "idle" | "running" | "done" | "error" | "interrupted";
  phase?: string;
  processed?: number;
  total?: number | null;
  message?: string;
  detail?: string | null;
  log?: ActivityLogEntry[];
  elapsed_seconds?: number;
  seconds_since_heartbeat?: number;
  /** Estimated remaining time, only after some work (see import_job._estimate) */
  eta_seconds?: number;
  /** An interrupted or failed import can continue where it stopped */
  can_resume?: boolean;
  resumed?: boolean;
  started_at?: string;
  finished_at?: string;
}

export interface Activity extends ImportStatus {
  id: string;
  title: string;
}

/** Last run of a scheduled background task (Celery), see backend/services/task_activity.py */
export interface ScheduledTask {
  id: string;
  title: string;
  /** In words, for example "alle 6 Stunden" */
  schedule: string;
  state: "never" | "running" | "ok" | "error" | "interrupted";
  started_at?: string;
  finished_at?: string;
  message?: string;
}

export interface ActivityResponse {
  activities: Activity[];
  running: boolean;
  scheduled?: ScheduledTask[];
}

/** Settings page, see GET /admin/settings. Secrets only as "set / not set". */
export interface AdminSettings {
  smtp: {
    enabled: boolean;
    host: string;
    port: number;
    security: "starttls" | "ssl" | "none";
    username: string;
    password_set: boolean;
    from_email: string;
    from_name: string;
    /** Where the effective value comes from: database (this page), .env file or default */
    source: "db" | "env" | "default";
  };
  nvd: { api_key_set: boolean; source: "db" | "env" | "default" };
  registration_enabled: boolean;
  public_url: string;
  public_url_source: "db" | "env" | "default";
  branding: {
    name: string;
    name_is_default: boolean;
    accent: string;
    footer_text: string;
    url: string;
    has_logo_light: boolean;
    has_logo_dark: boolean;
    logo_light: string | null;
    logo_dark: string | null;
    default_name: string;
  };
}

export const MAX_LOGO_BYTES = 512 * 1024;

/** Upload a logo as the raw request body (PNG, JPEG or WebP). */
export async function uploadLogo(token: string, variant: "light" | "dark", file: File): Promise<AdminSettings> {
  const response = await fetch(`/api/v1/admin/settings/branding/logo/${variant}`, {
    method: "PUT",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": file.type || "application/octet-stream" },
    body: file,
  });
  const body = await response.json().catch(() => null);
  if (!response.ok) throw new ApiError(messageOf(body, `Fehler ${response.status}`), response.status);
  return body as AdminSettings;
}
