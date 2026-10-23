/**
 * Address of the backend API.
 *
 * Browser: empty, so every request goes to the page's own address
 * (`/api/v1/...`). In production nginx forwards `/api` to the backend, in
 * development the rewrite in `next.config.js` does. Only if the API runs on
 * a different address, set NEXT_PUBLIC_API_URL when BUILDING the frontend.
 *
 * Server (rendering on the server): the backend is reached directly, inside
 * the Docker network (`API_URL=http://backend:8001`) or on localhost.
 */
export function apiBase(): string {
  if (typeof window === "undefined") {
    return process.env.API_URL || process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8001";
  }
  return process.env.NEXT_PUBLIC_API_URL || "";
}
