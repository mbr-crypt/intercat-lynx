/**
 * fetch() for the data endpoints, which are only open to signed-in users.
 *
 * Adds the access token. When the server says the session is no longer valid
 * (401), the stored token is dropped and the user is sent to the sign-in page,
 * which brings them back here afterwards.
 */

export const TOKEN_KEY = "auth_token";

/**
 * Only paths on this site: never an address typed into the URL by someone else.
 *
 * Browsers delete TAB, LF and CR anywhere in a URL before parsing it, so
 * "/<TAB>/evil.example" starts with "/" and not with "//" but still becomes
 * "https://evil.example/". Control characters and backslashes are therefore
 * refused outright, and what is left is resolved against a dummy origin: only a
 * result that stays on that origin is accepted, and only path, query and
 * fragment are handed back.
 */
export function safeNext(value: string | null | undefined): string {
  if (!value || !value.startsWith("/") || value.startsWith("//")) return "/";
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f\\]/.test(value)) return "/";
  let local: string;
  try {
    const base = "http://self.invalid";
    const url = new URL(value, base);
    if (url.origin !== base) return "/";
    local = url.pathname + url.search + url.hash;
  } catch {
    return "/";
  }
  if (local === "/auth" || local.startsWith("/auth?") || local.startsWith("/setup")) return "/";
  return local;
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
