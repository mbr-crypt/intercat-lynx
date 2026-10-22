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
    throw new Error(messageOf(body, `Fehler ${response.status}`));
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
  admin: "Alles, inklusive Benutzerverwaltung",
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
};

export function formatDate(value: string | null): string {
  if (!value) return "nie";
  return new Date(value).toLocaleString("de-DE", { dateStyle: "short", timeStyle: "short" });
}
