package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	// Bind address (Infra port policy: app services >8000 on loopback).
	Bind string

	// Postgres DSN, e.g. postgres://dyatel:pw@127.0.0.1:5432/dyatel.
	DatabaseDSN string

	// Reconcile tick interval in seconds.
	ReconcileEverySec int

	// Daemon node identity: each daemon reconciles only hosts where
	// hosts.node = Node (multi-node, one shared PG, RFC §4).
	Node string

	// Berg-side tunnel networks, one pair per transport: WG is the default and
	// inherits the legacy single-pair settings, AWG may live in its own space
	// (a separate subnet keeps the two transports' AllowedIPs and reply routes
	// unambiguous when one peer dials several gateways).
	TunnelIPv4NetWG  string // e.g. 10.66.66.0/24
	TunnelIPv6NetWG  string // e.g. fd66:66::/64
	TunnelIPv4NetAWG string // e.g. 10.77.77.0/24
	TunnelIPv6NetAWG string // e.g. fd77:77::/64

	// Host part allocation bounds inside a tunnel network: the gateway holds
	// .1 and hosts are carved from HostIPMin upward. The default leaves .1
	// alone so memorable low numbers (.6, .7) stay pinnable.
	HostIPMin int
	HostIPMax int

	// AmneziaWG inner MTU. Obfuscation (junk packets + magic headers) eats
	// headroom, and IPv6 has a hard 1280-byte floor (RFC 8200), so AWG pins the
	// inner MTU instead of letting wg-quick guess from the underlay.
	AWGMTU int

	// Per-host listen port pool per transport.
	PortPoolWGMin   int
	PortPoolWGMax   int
	PortPoolAWGMin  int
	PortPoolAWGMax  int
	PortPoolXrayMin int
	PortPoolXrayMax int

	// Public endpoint hosts used in rendered configs.
	PublicEndpointHost string // e.g. dyatel.test.nada.mu
	PublicIPv4         string // e.g. 81.30.105.65 (for DNS A records)
	PublicIPv6         string // e.g. 2a13:d207:494:21::1 (for DNS AAAA records)
	CoreListenIP       string // berg's wg interface address, e.g. 10.13.36.1

	// Authentik
	OIDCIntrospectionURL string // userinfo/introspection for admin group sync
	OIDCClientID         string
	OIDCClientSecret     string
	AuthentikAdminGroup  string
	// TrustSubHeader enables the X-Dyatel-Sub identity path for a fronting
	// proxy that authenticates users itself. It is off by default: the header
	// is plain text, so honouring it unconditionally lets any client that can
	// reach the API impersonate anyone (including an admin-group name).
	TrustSubHeader bool

	// Break-glass admin (works when Authentik is down).
	FallbackAdminUser string
	FallbackAdminHash string // argon2id PHC string

	// Reconcile targets.
	WGConfigPath    string // berg-side wg-dyatel.conf the loop manages
	XrayConfigPath  string // aggregated berg-side xray config (one process per node)
	XrayServiceName string // systemd template instance, e.g. xray@dyatel
	WGIfname        string // e.g. wg-dyatel
	UFWBinary       string

	CloudflareToken string // optional CF Zone:DNS:Edit token
	DNSZone         string // e.g. test.nada.mu
	// DNSSyncSec is the drift-check cadence; mutations sync immediately via
	// Trigger, so the periodic pass only heals out-of-band changes.
	DNSSyncSec int
}

func Load() (*Config, error) {
	c := load()
	if c.DatabaseDSN == "" {
		return nil, fmt.Errorf("DYATEL_DB_DSN is required")
	}
	return c, nil
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

// envBool is deliberately strict: only an explicit "true"/"1" turns a
// security-relevant switch on, so a typo can never widen the attack surface.
func envBool(key string, def bool) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "1", "true", "yes":
		return true
	case "0", "false", "no":
		return false
	}
	return def
}

// NetV4 returns the tunnel IPv4 network for a transport. Unknown transports
// fall back to the WireGuard pair: they share the same addressing model.
func (c *Config) NetV4(transport string) string {
	if transport == "amneziawg" {
		return c.TunnelIPv4NetAWG
	}
	return c.TunnelIPv4NetWG
}

// NetV6 returns the tunnel IPv6 network for a transport.
func (c *Config) NetV6(transport string) string {
	if transport == "amneziawg" {
		return c.TunnelIPv6NetAWG
	}
	return c.TunnelIPv6NetWG
}

// GatewayIP is the gateway address inside the transport's IPv4 network: the
// first host address (.1). Networks are per transport, so .1 is unambiguous
// even when one peer dials the same gateway over both transports.
func (c *Config) GatewayIP(transport string) string {
	_, cidr, err := net.ParseCIDR(c.NetV4(transport))
	if err != nil {
		return c.CoreListenIP
	}
	ip := make(net.IP, len(cidr.IP))
	copy(ip, cidr.IP)
	ip[len(ip)-1] = 1
	return ip.String()
}

// GatewayIPv6 is the gateway address inside the transport's IPv6 network.
func (c *Config) GatewayIPv6(transport string) string {
	_, cidr, err := net.ParseCIDR(c.NetV6(transport))
	if err != nil {
		return "fd66:66::1"
	}
	ip := make(net.IP, len(cidr.IP))
	copy(ip, cidr.IP)
	ip[len(ip)-1] = 1
	return ip.String()
}

func load() *Config {
	c := &Config{
		Bind:                 env("DYATEL_BIND", "127.0.0.1:8100"),
		DatabaseDSN:          env("DYATEL_DB_DSN", ""),
		ReconcileEverySec:    envInt("DYATEL_RECONCILE_EVERY", 15),
		Node:                 env("DYATEL_NODE", "test"),
		TunnelIPv4NetWG:      env("DYATEL_TUNNEL_V4_WG", env("DYATEL_TUNNEL_V4", "10.66.66.0/24")),
		TunnelIPv6NetWG:      env("DYATEL_TUNNEL_V6_WG", env("DYATEL_TUNNEL_V6", "fd66:66::/64")),
		TunnelIPv4NetAWG:     env("DYATEL_TUNNEL_V4_AWG", env("DYATEL_TUNNEL_V4_WG", env("DYATEL_TUNNEL_V4", "10.66.66.0/24"))),
		TunnelIPv6NetAWG:     env("DYATEL_TUNNEL_V6_AWG", env("DYATEL_TUNNEL_V6_WG", env("DYATEL_TUNNEL_V6", "fd66:66::/64"))),
		HostIPMin:            envInt("DYATEL_HOST_IP_MIN", 2),
		HostIPMax:            envInt("DYATEL_HOST_IP_MAX", 250),
		AWGMTU:               envInt("DYATEL_AWG_MTU", 1280),
		PortPoolWGMin:        envInt("DYATEL_WG_PORTS_MIN", 51820),
		PortPoolWGMax:        envInt("DYATEL_WG_PORTS_MAX", 51899),
		PortPoolAWGMin:       envInt("DYATEL_AWG_PORTS_MIN", 51900),
		PortPoolAWGMax:       envInt("DYATEL_AWG_PORTS_MAX", 51999),
		PortPoolXrayMin:      envInt("DYATEL_XRAY_PORTS_MIN", 5200),
		PortPoolXrayMax:      envInt("DYATEL_XRAY_PORTS_MAX", 5299),
		PublicEndpointHost:   env("DYATEL_PUBLIC_ENDPOINT", "dyatel.test.nada.mu"),
		PublicIPv4:           env("DYATEL_PUBLIC_IPV4", ""),
		PublicIPv6:           env("DYATEL_PUBLIC_IPV6", ""),
		CoreListenIP:         env("DYATEL_CORE_LISTEN_IP", "10.13.36.1"),
		OIDCIntrospectionURL: env("DYATEL_OIDC_INTROSPECTION_URL", ""),
		OIDCClientID:         env("DYATEL_OIDC_CLIENT_ID", ""),
		OIDCClientSecret:     env("DYATEL_OIDC_CLIENT_SECRET", ""),
		AuthentikAdminGroup:  env("DYATEL_OIDC_ADMIN_GROUP", "Dyatel Admins"),
		TrustSubHeader:       envBool("DYATEL_TRUST_SUB_HEADER", false),
		FallbackAdminUser:    env("DYATEL_FALLBACK_ADMIN_USER", ""),
		FallbackAdminHash:    env("DYATEL_FALLBACK_ADMIN_HASH", ""),
		WGConfigPath:         env("DYATEL_WG_CONFIG_PATH", "/etc/wireguard/wg-dyatel.conf"),
		XrayConfigPath:       env("DYATEL_XRAY_CONFIG_PATH", "/etc/xray/dyatel.json"),
		XrayServiceName:      env("DYATEL_XRAY_SERVICE", "xray@dyatel"),
		WGIfname:             env("DYATEL_WG_IFNAME", "wg-dyatel"),
		UFWBinary:            env("DYATEL_UFW_PATH", "/usr/sbin/ufw"),
		CloudflareToken:      env("DYATEL_CLOUDFLARE_TOKEN", ""),
		DNSZone:              env("DYATEL_DNS_ZONE", "test.nada.mu"),
		DNSSyncSec:           envInt("DYATEL_DNS_SYNC_SEC", 300),
	}
	return c
}

// LoadForRender returns the same env-driven settings but without the DSN
// requirement: offline rendering (dyatelctl gen) needs the network/port
// defaults, never the database. Tier 0 = playbook + pure renderers.
func LoadForRender() *Config {
	return load()
}
