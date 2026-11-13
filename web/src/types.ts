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