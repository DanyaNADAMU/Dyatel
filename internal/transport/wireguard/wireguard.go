package wireguard

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"text/template"

	"nadamu/dyatel/internal/config"
	"nadamu/dyatel/internal/store"
)

// Placeholder filled in locally by dyatelctl or the ansible role;
// the core never holds a user private key (RFC §3.4b).
const PrivateKeyPlaceholder = "{{PRIVATE_KEY}}"

// WG renders wireguard / amneziawg configs.
// Topology per host (RFC §4a): one berg-side wg interface per host
// (kernel ifname limit 15), ListenPort = host's pool port; two peers —
// proxer and consumer — both dialing in with BYOK keys; berg routes
// between them and NATs public ports to the proxer's tunnel IP.
type WG struct {
	cfg *config.Config
}

func New(cfg *config.Config) *WG { return &WG{cfg: cfg} }

// InterfaceName returns the per-host berg-side wg interface name.
func InterfaceName(h store.Host) string {
	max := 15 - len("wgd-")
	n := h.Name
	if len(n) > max {
		n = n[:max]
	}
	return "wgd-" + n
}

// RenderProxerConfig renders the owner-side wg-quick config.
func (w *WG) RenderProxerConfig(h store.Host) ([]byte, error) {
	return w.render(h, hostTpl)
}

// RenderClientConfig renders the consumer-side wg-quick config.
// Requires the consumer to have registered their BYOK public key
// (POST /hosts/{id}/consumer-key) so their tunnel IPs are allocated.
func (w *WG) RenderClientConfig(h store.Host) ([]byte, error) {
	if h.ConsumerWGPublicKey == nil || *h.ConsumerWGPublicKey == "" {
		return nil, fmt.Errorf("consumer key not registered")
	}
	if h.ConsumerTunnelIPv4 == nil || h.ConsumerTunnelIPv6 == nil {
		return nil, fmt.Errorf("consumer tunnel IPs not allocated")
	}
	return w.render(h, clientTpl)
}

func (w *WG) render(h store.Host, tpl *template.Template) ([]byte, error) {
	if len(h.Params) > 0 && !json.Valid(h.Params) {
		return nil, fmt.Errorf("bad params json")
	}
	data := struct {
		Host       store.Host
		Endpoint   string
		ListenIP   string
		GWIPv6     string
		Keepalive  int
		IsAWG      bool
		PrivateKey string
	}{
		Host:       h,
		Endpoint:   w.cfg.PublicEndpointHost,
		ListenIP:   w.cfg.CoreListenIP,
		GWIPv6:     gwIPv6(w.cfg),
		Keepalive:  h.Keepalive,
		IsAWG:      h.Transport == "amneziawg",
		PrivateKey: PrivateKeyPlaceholder,
	}
	var buf bytes.Buffer
	if err := tpl.Execute(&buf, data); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

const hostTplStr = `[Interface]
Address = {{.Host.TunnelIPv4}}, {{.Host.TunnelIPv6}}
PrivateKey = {{.PrivateKey}}
{{- if .IsAWG }}
{{- /* AWG obfuscation params injected in phase 1b from hosts.params */}}
{{- end }}

# berg (core) — dial in; this side never listens
[Peer]
PublicKey = {{.Host.GWPublicKey}}
PresharedKey = {{.Host.WGPreSharedKey}}
Endpoint = {{.Endpoint}}:{{.Host.ListenPort}}
AllowedIPs = {{.ListenIP}}/32, {{.GWIPv6}}/128
PersistentKeepalive = {{.Keepalive}}
`

const clientTplStr = `[Interface]
Address = {{.Host.ConsumerTunnelIPv4}}, {{.Host.ConsumerTunnelIPv6}}
PrivateKey = {{.PrivateKey}}

# proxer host {{.Host.Name}} (routed via berg)
[Peer]
PublicKey = {{.Host.GWPublicKey}}
PresharedKey = {{.Host.WGPreSharedKey}}
Endpoint = {{.Endpoint}}:{{.Host.ListenPort}}
AllowedIPs = {{.Host.TunnelIPv4}}, {{.Host.TunnelIPv6}}
PersistentKeepalive = {{.Keepalive}}
`

var (
	hostTpl   = template.Must(template.New("host").Parse(hostTplStr))
	clientTpl = template.Must(template.New("client").Parse(clientTplStr))
)

// RenderGWConfig renders the berg-side config for one host.
func (w *WG) RenderGWConfig(h store.Host) ([]byte, error) {
	if h.State != "active" {
		return nil, nil // suspended hosts: interface absent (reconcile removes)
	}
	var b strings.Builder
	b.WriteString("# Managed by dyatel-core. Do not edit.\n")
	b.WriteString("[Interface]\n")
	b.WriteString(fmt.Sprintf("Address = %s/32, %s/128\n", w.cfg.CoreListenIP, gwIPv6(w.cfg)))
	b.WriteString(fmt.Sprintf("ListenPort = %d\n", h.ListenPort))
	b.WriteString(fmt.Sprintf("PrivateKey = %s\n", h.GWPrivateKey))
	b.WriteString("Table = off\n")
	b.WriteString(fmt.Sprintf("# proxer %s (%s)\n", h.Name, h.Transport))
	b.WriteString(fmt.Sprintf("[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = %s, %s\n\n",
		h.WGPublicKey, h.WGPreSharedKey,
		strings.TrimSuffix(h.TunnelIPv4, "/32"), strings.TrimSuffix(h.TunnelIPv6, "/128")))
	if h.ConsumerWGPublicKey != nil && *h.ConsumerWGPublicKey != "" && h.ConsumerTunnelIPv4 != nil {
		b.WriteString("# consumer\n")
		b.WriteString(fmt.Sprintf("[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = %s, %s\n\n",
			*h.ConsumerWGPublicKey, h.WGPreSharedKey,
			strings.TrimSuffix(*h.ConsumerTunnelIPv4, "/32"),
			strings.TrimSuffix(deref(h.ConsumerTunnelIPv6), "/128")))
	}
	return []byte(b.String()), nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func gwIPv6(c *config.Config) string {
	if _, cidr, err := net.ParseCIDR(c.TunnelIPv6Net); err == nil {
		ip := make(net.IP, len(cidr.IP))
		copy(ip, cidr.IP)
		ip[len(ip)-1] = 1
		return ip.String()
	}
	return "fd00:36::1"
}