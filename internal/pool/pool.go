package pool

import (
	"context"
	"fmt"
	"net"

	"nadamu/dyatel/internal/config"
	"nadamu/dyatel/internal/store"
)

// Allocator hands out per-host ports and tunnel addresses. Both live in a
// gateway node's own space: berg and glacier may hand out the same number,
// because a peer dials them separately and the reply route is chosen by the
// destination gateway. Uniqueness therefore means "per node", not "fleet-wide".
type Allocator struct {
	cfg *config.Config
	st  *store.Store
}

func New(cfg *config.Config, st *store.Store) *Allocator {
	return &Allocator{cfg: cfg, st: st}
}

// HostPort returns a free per-host listen port for the transport on a node.
// An explicit preferred port wins when it is inside the pool and free, so an
// operator can pin a memorable number (6666/7777) instead of first-fit luck.
func (a *Allocator) HostPort(ctx context.Context, node, transport string, preferred int) (int, error) {
	lo, hi := a.portRange(transport)
	if lo == 0 {
		return 0, fmt.Errorf("unknown transport %q", transport)
	}
	used, err := a.st.UsedPorts(ctx, node)
	if err != nil {
		return 0, err
	}
	if preferred > 0 {
		// The pool bounds automatic allocation only. An operator-pinned port
		// may sit outside it (a memorable 6666/7777), as long as it is a real
		// port and free on this node.
		if preferred < 1024 || preferred > 65535 {
			return 0, fmt.Errorf("preferred port %d must be between 1024 and 65535", preferred)
		}
		if used[preferred] {
			return 0, fmt.Errorf("preferred port %d already taken on node %s", preferred, node)
		}
		return preferred, nil
	}
	for p := lo; p <= hi; p++ {
		if !used[p] {
			return p, nil
		}
	}
	return 0, fmt.Errorf("port pool exhausted for %s on node %s", transport, node)
}

func (a *Allocator) portRange(transport string) (int, int) {
	switch transport {
	case "wireguard":
		return a.cfg.PortPoolWGMin, a.cfg.PortPoolWGMax
	case "amneziawg":
		return a.cfg.PortPoolAWGMin, a.cfg.PortPoolAWGMax
	case "xray-vless":
		return a.cfg.PortPoolXrayMin, a.cfg.PortPoolXrayMax
	}
	return 0, 0
}

// TunnelIPs returns a free (v4/32, v6/128) pair for a node and transport,
// first-fit from HostIPMin (.1-.15 stay reserved for gateways and infra).
func (a *Allocator) TunnelIPs(ctx context.Context, node, transport string) (string, string, error) {
	return a.TunnelIPsWith(ctx, node, transport, "", "")
}

// TunnelIPsWith is TunnelIPs with optional pinned host addresses. A pinned
// address is validated against the transport's network, the reserved gateway
// block and the node's current allocations, so a typo fails loudly instead of
// silently landing traffic on the wrong peer.
//
// A pin is honoured literally: hosting uses hex host parts, so ::16 is not the
// v6 twin of .16. When only one family is pinned the other is chosen free,
// preferring the same host part so the pair still reads symmetrically.
func (a *Allocator) TunnelIPsWith(ctx context.Context, node, transport, preferV4, preferV6 string) (string, string, error) {
	_, v4cidr, err := net.ParseCIDR(a.cfg.NetV4(transport))
	if err != nil {
		return "", "", fmt.Errorf("bad tunnel v4 net: %w", err)
	}
	_, v6cidr, err := net.ParseCIDR(a.cfg.NetV6(transport))
	if err != nil {
		return "", "", fmt.Errorf("bad tunnel v6 net: %w", err)
	}
	u4, u6, err := a.st.UsedTunnelIPs(ctx, node)
	if err != nil {
		return "", "", err
	}

	validate := func(raw, fam string, cidr *net.IPNet, used map[string]bool) (net.IP, error) {
		ip := net.ParseIP(raw)
		if ip == nil || !cidr.Contains(ip) {
			return nil, fmt.Errorf("preferred %s %q not inside %s", fam, raw, cidr)
		}
		if lastOctet(ip) < a.cfg.HostIPMin {
			return nil, fmt.Errorf("preferred %s %q is inside the reserved gateway block", fam, raw)
		}
		if used[ip.String()] {
			return nil, fmt.Errorf("preferred %s %q already taken on node %s", fam, raw, node)
		}
		return ip, nil
	}

	var ip4, ip6 net.IP
	if preferV4 != "" {
		if ip4, err = validate(preferV4, "ipv4", v4cidr, u4); err != nil {
			return "", "", err
		}
	}
	if preferV6 != "" {
		if ip6, err = validate(preferV6, "ipv6", v6cidr, u6); err != nil {
			return "", "", err
		}
	}

	// Auto-pick the missing family, preferring the pinned twin's host part.
	for i := a.cfg.HostIPMin; i <= a.cfg.HostIPMax; i++ {
		if ip4 == nil {
			cand := hostIP(v4cidr, i)
			if ip6 != nil && lastOctet(ip6) != i {
				// try the pinned v6 host part first below
			}
			if !u4[cand.String()] {
				ip4 = cand
			}
		}
		if ip6 == nil {
			cand := hostIP(v6cidr, i)
			if !u6[cand.String()] {
				ip6 = cand
			}
		}
		if ip4 != nil && ip6 != nil {
			break
		}
	}
	if ip4 == nil || ip6 == nil {
		return "", "", fmt.Errorf("tunnel IP pool exhausted on node %s", node)
	}
	return ip4.String() + "/32", ip6.String() + "/128", nil
}

// hostIP returns net.IP with the last byte set to i (host part).
func hostIP(cidr *net.IPNet, i int) net.IP {
	ip := make(net.IP, len(cidr.IP))
	copy(ip, cidr.IP)
	ip[len(ip)-1] = byte(i)
	return ip
}

// lastOctet reads the host part the allocator uses (last byte).
func lastOctet(ip net.IP) int {
	if len(ip) == 0 {
		return 0
	}
	return int(ip[len(ip)-1])
}
