// API wire types mirroring internal/store structs (JSON tags).
// The panel never imports Go internals; it only consumes /api/v1 JSON.

export interface Me {
  id: string;
  sub: string;
  name: string;
  is_admin: boolean;
  auth: "oidc" | "pat" | "fallback";
}

export interface Host {
  id: string;
  name: string;
  node: string;
  owner_id: string;
  consumer_id: string;
  wg_public_key: string;
  gw_public_key: string;
  tunnel_ipv4: string;
  tunnel_ipv6: string;
  consumer_wg_public_key?: string | null;
  consumer_tunnel_ipv4?: string | null;
  consumer_tunnel_ipv6?: string | null;
  endpoint?: string | null;
  transport: "wireguard" | "amneziawg" | "xray-vless";
  listen_port: number;
  params?: Record<string, unknown> | null;
  keepalive: number;
  state: string;
}

export interface Forward {
  id: string;
  host_id: string;
  public_port: number;
  target_port: number;
  proto: "tcp" | "udp";
  label: string;
}

export interface DNSRecord {
  id: string;
  forward_id: string;
  name: string;
  cloudflare_id?: string | null;
  created_at: string;
}

export interface PeerEndpointStatus {
  public_key: string;
  endpoint?: string;
  last_handshake?: string;
  transfer_rx?: number;
  transfer_tx?: number;
}

export interface HostRuntimeStatus {
  name: string;
  interface: string;
  state: string;
  listen_port: number;
  transport: string;
  endpoints: Record<string, PeerEndpointStatus>;
  drift: boolean;
  last_error?: string;
}

export interface DNSStatus {
  enabled: boolean;
  last_sync?: string;
  last_error?: string;
}

export interface StatusResponse {
  _checked_at?: string;
  _error?: HostRuntimeStatus;
  _dns?: DNSStatus;
  [hostID: string]: unknown;
}

export interface Token {
  id: string;
  label: string;
  created_at: string;
  last_used_at?: string | null;
  revoked_at?: string | null;
  /** Present only in the create response: the one time the secret is shown. */
  token?: string;
}

export interface UserInfo {
  id: string;
  display_name: string;
  is_admin: boolean;
}

export interface EventItem {
  id: number;
  at: string;
  user_id?: string | null;
  auth_method: "oidc" | "pat" | "fallback";
  action: string;
  object_type: string;
  object_id: string;
}