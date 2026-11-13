package config

import (
	"fmt"
	"os"
	"strconv"
)

type Config struct {
	// Bind address (Infra port policy: app services >8000 on loopback).
	Bind string

	// Postgres DSN, e.g. postgres://dyatel:pw@127.0.0.1:5432/dyatel.
	DatabaseDSN string

	// Reconcile tick interval in seconds.
	ReconcileEverySec int

	// Berg-side tunnel network: per-host /32 and /128 are carved out of it.
	TunnelIPv4Net string // e.g. 10.13.36.0/24
	TunnelIPv6Net string // e.g. fd00:36::/64

	// Per-host listen port pool per transport.
	PortPoolWGMin     int
	PortPoolWGMax     int
	PortPoolAWGMin    int
	PortPoolAWGMax    int
	PortPoolXrayMin   int
	PortPoolXrayMax   int

	// Public endpoint hosts used in rendered configs.
	PublicEndpointHost string // e.g. dyatel.test.nada.mu
	CoreListenIP       string // berg's wg interface address, e.g. 10.13.36.1

	// Authentik
	OIDCIntrospectionURL string // userinfo/introspection for admin group sync
	OIDCClientID         string
	OIDCClientSecret      string
	AuthentikAdminGroup   string

	// Break-glass admin (works when Authentik is down).
	FallbackAdminUser string
	FallbackAdminHash string // argon2id PHC string

	// Reconcile targets.
	WGConfigPath string // berg-side wg-dyatel.conf the loop manages
	WGIfname     string // e.g. wg-dyatel
	UFWBinary    string

	DNSZone string // e.g. test.nada.mu (records under it, CF later)
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func Load() (*Config, error) {
	c := &Config{
		Bind:                env("DYATEL_BIND", "127.0.0.1:8100"),
		DatabaseDSN:         env("DYATEL_DB_DSN", ""),
		ReconcileEverySec:   envInt("DYATEL_RECONCILE_EVERY", 15),
		TunnelIPv4Net:       env("DYATEL_TUNNEL_V4", "10.13.36.0/24"),
		TunnelIPv6Net:       env("DYATEL_TUNNEL_V6", "fd00:36::/64"),
		PortPoolWGMin:       envInt("DYATEL_WG_PORTS_MIN", 51820),
		PortPoolWGMax:       envInt("DYATEL_WG_PORTS_MAX", 51899),
		PortPoolAWGMin:      envInt("DYATEL_AWG_PORTS_MIN", 51900),
		PortPoolAWGMax:      envInt("DYATEL_AWG_PORTS_MAX", 51999),
		PortPoolXrayMin:     envInt("DYATEL_XRAY_PORTS_MIN", 5200),
		PortPoolXrayMax:     envInt("DYATEL_XRAY_PORTS_MAX", 5299),
		PublicEndpointHost:  env("DYATEL_PUBLIC_ENDPOINT", "dyatel.test.nada.mu"),
		CoreListenIP:        env("DYATEL_CORE_LISTEN_IP", "10.13.36.1"),
		OIDCIntrospectionURL: env("DYATEL_OIDC_INTROSPECTION_URL", ""),
		OIDCClientID:        env("DYATEL_OIDC_CLIENT_ID", ""),
		OIDCClientSecret:    env("DYATEL_OIDC_CLIENT_SECRET", ""),
		AuthentikAdminGroup: env("DYATEL_OIDC_ADMIN_GROUP", "Dyatel Admins"),
		FallbackAdminUser:   env("DYATEL_FALLBACK_ADMIN_USER", ""),
		FallbackAdminHash:   env("DYATEL_FALLBACK_ADMIN_HASH", ""),
		WGConfigPath:        env("DYATEL_WG_CONFIG_PATH", "/etc/wireguard/wg-dyatel.conf"),
		WGIfname:            env("DYATEL_WG_IFNAME", "wg-dyatel"),
		UFWBinary:           env("DYATEL_UFW_PATH", "/usr/sbin/ufw"),
		DNSZone:             env("DYATEL_DNS_ZONE", "test.nada.mu"),
	}
	if c.DatabaseDSN == "" {
		return nil, fmt.Errorf("DYATEL_DB_DSN is required")
	}
	return c, nil
}