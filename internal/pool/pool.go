package pool

import (
	"context"
	"fmt"
	"net"

	"nadamu/dyatel/internal/config"
	"nadamu/dyatel/internal/store"
)

type Allocator struct {
	cfg *config.Config
	st  *store.Store
}

func New(cfg *config.Config, st *store.Store) *Allocator {
	return &Allocator{cfg: cfg, st: st}
}

// HostPort returns a free per-host listen port for the transport.
func (a *Allocator) HostPort(ctx context.Context, transport string) (int, error) {
	var lo, hi int
	switch transport {
	case "wireguard":
		lo, hi = a.cfg.PortPoolWGMin, a.cfg.PortPoolWGMax
	case "amneziawg":
		lo, hi = a.cfg.PortPoolAWGMin, a.cfg.PortPoolAWGMax
	case "xray-vless":
		lo, hi = a.cfg.PortPoolXrayMin, a.cfg.PortPoolXrayMax
	default:
		return 0, fmt.Errorf("unknown transport %q", transport)
	}
	used, err := a.st.UsedPorts(ctx)
	if err != nil {
		return 0, err
	}
	for p := lo; p <= hi; p++ {
		if !used[p] {
			return p, nil
		}
	}
	return 0, fmt.Errorf("port pool exhausted for %s", transport)
}

// TunnelIPs returns a free (v4/32, v6/128) pair, first-fit, .2–.250
// (.1 is the core itself).
func (a *Allocator) TunnelIPs(ctx context.Context) (string, string, error) {
	_, v4cidr, err := net.ParseCIDR(a.cfg.TunnelIPv4Net)
	if err != nil {
		return "", "", fmt.Errorf("bad tunnel v4 net: %w", err)
	}
	_, v6cidr, err := net.ParseCIDR(a.cfg.TunnelIPv6Net)
	if err != nil {
		return "", "", fmt.Errorf("bad tunnel v6 net: %w", err)
	}
	u4, u6, err := a.st.UsedTunnelIPs(ctx)
	if err != nil {
		return "", "", err
	}
	for i := 2; i <= 250; i++ {
		ip4 := hostIP(v4cidr, i)
		if u4[ip4.String()] {
			continue
		}
		ip6 := hostIP(v6cidr, i)
		if u6[ip6.String()] {
			continue
		}
		return ip4.String() + "/32", ip6.String() + "/128", nil
	}
	return "", "", fmt.Errorf("tunnel IP pool exhausted")
}

// hostIP returns net.IP with the last byte set to i (host part).
func hostIP(cidr *net.IPNet, i int) net.IP {
	ip := make(net.IP, len(cidr.IP))
	copy(ip, cidr.IP)
	ip[len(ip)-1] = byte(i)
	return ip
}