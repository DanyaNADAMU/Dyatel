import type { Forward, Host, Me } from "./types";
import { authHeader, getCred } from "./session";

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

// The core is on loopback behind an nginx vhost; /api/v1 is same-origin.
async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const h = authHeader(getCred());
  const r = await fetch(`/api/v1${path}`, {
    ...init,
    headers: {
      ...(h ? { Authorization: h } : {}),
      ...(init?.body ? { "Content-Type": "application/json" } : {}),
      ...(init?.headers ?? {}),
    },
  });
  if (!r.ok) {
    let msg = `${r.status}`;
    try {
      // Errors are plain text status strings from the core.
      msg = (await r.text()) || msg;
    } catch {
      /* keep status */
    }
    throw new ApiError(r.status, msg);
  }
  if (r.status === 204) return undefined as T;
  const ct = r.headers.get("content-type") ?? "";
  if (ct.startsWith("application/json")) return (await r.json()) as T;
  return (await r.text()) as unknown as T;
}

// chi routes carry trailing slashes on collection endpoints ("/hosts/") —
// these helpers keep every request aligned with api.go registrations.
export const api = {
  me: () => req<Me>("/me"),
  hosts: () => req<Host[]>("/hosts/"),
  host: (id: string) => req<Host>(`/hosts/${id}/`),
  createHost: (b: {
    name: string;
    wg_public_key: string;
    transport: string;
    consumer_id: string;
    keepalive?: number;
    params?: unknown;
  }) =>
    req<Host>("/hosts/", {
      method: "POST",
      body: JSON.stringify(b),
    }),
  deleteHost: (id: string) => req<void>(`/hosts/${id}/`, { method: "DELETE" }),
  setConsumerKey: (id: string, wg_public_key: string) =>
    req<void>(`/hosts/${id}/consumer-key`, {
      method: "POST",
      body: JSON.stringify({ wg_public_key }),
    }),
  setState: (id: string, state: string) =>
    req<void>(`/hosts/${id}/state`, {
      method: "POST",
      body: JSON.stringify({ state }),
    }),
  forwards: (hostId: string) => req<Forward[]>(`/hosts/${hostId}/forwards/`),
  createForward: (
    hostId: string,
    b: { public_port: number; target_port: number; proto: string; label: string },
  ) =>
    req<Forward>(`/hosts/${hostId}/forwards/`, {
      method: "POST",
      body: JSON.stringify(b),
    }),
  deleteForward: (hostId: string, fid: string) =>
    req<void>(`/hosts/${hostId}/forwards/${fid}`, { method: "DELETE" }),
  proxerConfig: (id: string) => req<string>(`/hosts/${id}/config/proxer`),
  clientConfig: (id: string) => req<string>(`/hosts/${id}/config/client`),
  status: () => req<Record<string, unknown>>("/status"),
};
