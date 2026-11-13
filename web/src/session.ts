// Panel-side credential holder. Two shapes exist on purpose:
//  - oidc  — normal humans, access token from Authentik code flow (PKCE);
//  - basic — the single break-glass fallback admin (RFC §3.1), kept only in
//            sessionStorage so it dies with the tab and never hits disk.
//
// Authorization is always a single header value; the API client does not
// care where it came from.

export type Credential = { auth: "oidc"; token: string } | { auth: "basic"; header: string };

const KEY = "dyatel.cred";

export function getCred(): Credential | null {
  const raw = sessionStorage.getItem(KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as Credential;
  } catch {
    return null;
  }
}

export function setCred(c: Credential): void {
  sessionStorage.setItem(KEY, JSON.stringify(c));
}

export function clearCred(): void {
  sessionStorage.removeItem(KEY);
}

export function authHeader(c: Credential | null): string | undefined {
  if (!c) return undefined;
  if (c.auth === "oidc") return `Bearer ${c.token}`;
  return c.header; // already "Basic base64(...)"
}
