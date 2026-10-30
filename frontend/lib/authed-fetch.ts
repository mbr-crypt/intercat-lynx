/**
 * fetch() for the data endpoints, which are only open to signed-in users.
 *
 * Adds the access token. When the server says the session is no longer valid
 * (401), the stored token is dropped and the user is sent to the sign-in page,
 * which brings them back here afterwards.
 */

export const TOKEN_KEY = "auth_token";

/** Only paths on this site: never an address typed into the URL by someone else. */
export function safeNext(value: string | null | undefined): string {
  if (!value || !value.startsWith("/") || value.startsWith("//") || value.startsWith("/\\")) return "/";
  if (value === "/auth" || value.startsWith("/auth?") || value.startsWith("/setup")) return "/";
  return value;
}

export function signInUrl(): string {
  const here = `${window.location.pathname}${window.location.search}`;
  return `/auth?next=${encodeURIComponent(safeNext(here))}`;
}

export async function authFetch(input: string, init: RequestInit = {}): Promise<Response> {
  let token: string | null = null;
  try {
    token = localStorage.getItem(TOKEN_KEY);
  } catch {
    // storage blocked: the request goes out without a token and is refused
  }
  const headers = new Headers(init.headers);
  if (token && !headers.has("Authorization")) headers.set("Authorization", `Bearer ${token}`);
  const response = await fetch(input, { ...init, headers });
  if (response.status === 401 && token) {
    try {
      localStorage.removeItem(TOKEN_KEY);
    } catch {
      // ignore
    }
    window.location.assign(signInUrl());
  }
  return response;
}
