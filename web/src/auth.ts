import { UserManager, type User } from "oidc-client-ts";

// Runtime config injected at build time by Vite (VITE_* env vars).
export const OIDC = {
  authority: import.meta.env.VITE_OIDC_AUTHORITY as string,
  client_id: import.meta.env.VITE_OIDC_CLIENT_ID as string,
};

export const mgr = new UserManager({
  authority: OIDC.authority,
  client_id: OIDC.client_id,
  redirect_uri: `${location.origin}${location.pathname}`,
  // The core introspects the access token server-side; the panel never
  // needs offline access because each visit re-runs the code flow.
  scope: "openid profile email",
});

export async function signin(): Promise<void> {
  await mgr.signinRedirect();
}

export async function complete(): Promise<User | null> {
  const u = await mgr.signinCallback();
  return u ?? null;
}

export async function signout(): Promise<void> {
  await mgr.signoutRedirect();
}
