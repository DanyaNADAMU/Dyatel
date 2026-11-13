// Package xrayvless renders xray configs for the xray-vless transport
// (RFC §3.4a, phase 2). Topology: one VLESS leg per host —
// consumer →(vless over TCP+TLS)→ berg — where berg terminates TLS and
// dials the real destination with a freedom outbound. The VLESS protocol
// carries the destination address itself, so berg needs no per-forward
// config: each consumer forward is a dokodemo-door inbound whose
// destination is proxer_endpoint:target_port, routed into the vless
// outbound. TLS is masking only; REALITY is deliberately rejected
// (ParseXrayParams) until a need proves otherwise.
package xrayvless

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"unicode"

	"github.com/google/uuid"
	"nadamu/dyatel/internal/config"
	"nadamu/dyatel/internal/store"
)

// Placeholders filled in locally by the operator on berg; the core never
// holds TLS private keys (same BYOK philosophy as RFC §3.4b).
const (
	CertPlaceholder = "{{DYATEL_CERT_PEM}}"
	KeyPlaceholder  = "{{DYATEL_KEY_PEM}}"
)

// XrayParams are the transport-specific knobs in hosts.params jsonb.
// sni / uuid / proxer_endpoint are required; the API injects the
// generated uuid before validation (pair-shared credential, like the PSK).
type XrayParams struct {
	SNI            string `json:"sni"`
	UUID           string `json:"uuid"`
	ProxerEndpoint string `json:"proxer_endpoint"`
	CertFile       string `json:"cert_file,omitempty"` // path on berg
	KeyFile        string `json:"key_file,omitempty"`  // path on berg
	AllowInsecure  bool   `json:"allow_insecure,omitempty"`
}

// Xray renders xray configs for one host.
type Xray struct {
	cfg *config.Config
}

func New(cfg *config.Config) *Xray { return &Xray{cfg: cfg} }

// ParseXrayParams decodes and validates hosts.params jsonb. REALITY
// parameters are rejected outright (any nesting depth): the transport
// is TLS masking only, and a pasted x25519 reality keypair must fail
// loudly instead of silently rendering a broken config.
func ParseXrayParams(raw []byte) (XrayParams, error) {
	if len(raw) == 0 || string(raw) == "{}" || string(raw) == "null" {
		return XrayParams{}, fmt.Errorf("xray params: sni, uuid and proxer_endpoint are required")
	}
	var m any
	if err := json.Unmarshal(raw, &m); err != nil {
		return XrayParams{}, fmt.Errorf("xray params: bad json: %w", err)
	}
	if k, ok := findForbiddenKey(m); ok {
		return XrayParams{}, fmt.Errorf("xray params: %q: Reality is not supported (TLS masking only)", k)
	}
	var p XrayParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return XrayParams{}, fmt.Errorf("xray params: %w", err)
	}
	if hasSpace(p.SNI) {
		return XrayParams{}, fmt.Errorf("xray params: sni must not contain whitespace")
	}
	if p.SNI == "" {
		return XrayParams{}, fmt.Errorf("xray params: sni is required")
	}
	if hasSpace(p.UUID) {
		return XrayParams{}, fmt.Errorf("xray params: uuid must not contain whitespace")
	}
	if _, err := uuid.Parse(p.UUID); err != nil {
		return XrayParams{}, fmt.Errorf("xray params: uuid is not a valid uuid: %w", err)
	}
	if hasSpace(p.ProxerEndpoint) {
		return XrayParams{}, fmt.Errorf("xray params: proxer_endpoint must not contain whitespace")
	}
	if p.ProxerEndpoint == "" {
		return XrayParams{}, fmt.Errorf("xray params: proxer_endpoint is required")
	}
	if hasSpace(p.CertFile) || hasSpace(p.KeyFile) {
		return XrayParams{}, fmt.Errorf("xray params: cert_file/key_file must not contain whitespace")
	}
	if p.KeyFile != "" && p.CertFile == "" {
		return XrayParams{}, fmt.Errorf("xray params: key_file requires cert_file")
	}
	return p, nil
}

// InjectUUID fills a missing "uuid" key with a freshly generated one and
// returns the params for validation/store. The VLESS uuid is a
// pair-shared credential like the wg PSK, so the core may generate it
// (BYOK covers private keys, not pair credentials).
func InjectUUID(raw []byte) ([]byte, error) {
	if len(raw) == 0 || string(raw) == "{}" || string(raw) == "null" {
		raw = []byte("{}")
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("xray params: bad json: %w", err)
	}
	if v, ok := m["uuid"]; ok {
		if s, isStr := v.(string); isStr && s != "" {
			return raw, nil // owner supplied one: keep it, validation checks the format
		}
	}
	m["uuid"] = uuid.NewString()
	out, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// findForbiddenKey walks the decoded params looking for reality-style
// keys at any depth (case-insensitive).
func findForbiddenKey(v any) (string, bool) {
	switch t := v.(type) {
	case map[string]any:
		for k, inner := range t {
			low := strings.ToLower(k)
			// Substring match so realitySettings-style wrappers are
			// caught too, not just a bare "reality" key.
			if low == "public_key" || low == "private_key" || strings.Contains(low, "reality") {
				return k, true
			}
			if name, bad := findForbiddenKey(inner); bad {
				return name, true
			}
		}
	case []any:
		for _, inner := range t {
			if name, bad := findForbiddenKey(inner); bad {
				return name, true
			}
		}
	}
	return "", false
}

func hasSpace(s string) bool {
	return strings.IndexFunc(s, unicode.IsSpace) >= 0
}

// proxerHost returns the destination prefix berg dials: the endpoint
// without its optional port (forwards always append their own
// :target_port).
func (p XrayParams) proxerHost() string {
	if host, _, err := net.SplitHostPort(p.ProxerEndpoint); err == nil {
		return host
	}
	return p.ProxerEndpoint
}

// ---- typed xray JSON shapes (exact xray lowerCamel field names) ----

type logCfg struct {
	LogLevel string `json:"loglevel"`
}

type streamSettings struct {
	Network     string       `json:"network"`
	Security    string       `json:"security"`
	TLSSettings *tlsSettings `json:"tlsSettings,omitempty"`
	TCPSettings *tcpSettings `json:"tcpSettings,omitempty"`
}

type tcpSettings struct {
	Header *tcpHeader `json:"header,omitempty"`
}

type tcpHeader struct {
	Type string `json:"type"`
}

type tlsSettings struct {
	ServerName    string        `json:"serverName,omitempty"`
	AllowInsecure bool          `json:"allowInsecure"`
	Certificates  []certificate `json:"certificates,omitempty"`
}

type certificate struct {
	CertificateFile string   `json:"certificateFile,omitempty"`
	KeyFile         string   `json:"keyFile,omitempty"`
	Certificate     []string `json:"certificate,omitempty"`
	Key             []string `json:"key,omitempty"`
}

type serverSettings struct {
	Clients    []vlessClient `json:"clients"`
	Decryption string        `json:"decryption"`
}

type vlessClient struct {
	ID   string `json:"id"`
	Flow string `json:"flow"`
	// "//" is tolerated inside objects too, but clients stay clean.
	Email string `json:"email,omitempty"`
}

type clientInbound struct {
	Listen         string           `json:"listen"`
	Port           int              `json:"port"`
	Protocol       string           `json:"protocol"`
	Settings       dokodemoSettings `json:"settings"`
	StreamSettings *streamSettings  `json:"streamSettings,omitempty"`
	Tag            string           `json:"tag"`
}

type dokodemoSettings struct {
	Address        string `json:"address"`
	Port           int    `json:"port"`
	Network        string `json:"network"`
	FollowRedirect bool   `json:"followRedirect"`
}

type vlessOutboundSettings struct {
	Vnext []vnextServer `json:"vnext"`
}

type vnextServer struct {
	Address string      `json:"address"`
	Port    int         `json:"port"`
	Users   []vlessUser `json:"users"`
}

type vlessUser struct {
	ID         string `json:"id"`
	Flow       string `json:"flow"`
	Security   string `json:"security"`
	Encryption string `json:"encryption"`
}

type outbound struct {
	Protocol       string          `json:"protocol"`
	Tag            string          `json:"tag,omitempty"`
	Settings       any             `json:"settings"`
	StreamSettings *streamSettings `json:"streamSettings,omitempty"`
}

type freedomSettings struct {
	DomainStrategy string `json:"domainStrategy,omitempty"`
}

type routing struct {
	Rules []routingRule `json:"rules"`
}

type routingRule struct {
	Type        string   `json:"type"`
	InboundTag  []string `json:"inboundTag"`
	OutboundTag string   `json:"outboundTag"`
}

type serverConfig struct {
	Comment   string          `json:"//,omitempty"`
	Log       *logCfg         `json:"log"`
	Inbounds  []serverInbound `json:"inbounds"`
	Outbounds []outbound      `json:"outbounds"`
}

type serverInbound struct {
	Listen         string         `json:"listen"`
	Port           int            `json:"port"`
	Protocol       string         `json:"protocol"`
	Settings       serverSettings `json:"settings"`
	StreamSettings streamSettings `json:"streamSettings"`
	Tag            string         `json:"tag,omitempty"`
}

type clientConfig struct {
	Comment   string          `json:"//,omitempty"`
	Log       *logCfg         `json:"log"`
	Inbounds  []clientInbound `json:"inbounds"`
	Outbounds []outbound      `json:"outbounds"`
	Routing   routing         `json:"routing"`
}

// RenderServerConfig renders the berg-side xray JSON: one vless inbound
// on the host's pool port with TLS masking, freedom as the first
// (routing-default) outbound. No per-forward config here: the VLESS
// protocol carries the destination address to berg.
func (x *Xray) RenderServerConfig(h store.Host) ([]byte, error) {
	p, err := ParseXrayParams(h.Params)
	if err != nil {
		return nil, err
	}
	// Certificates come from params: with cert_file set we point xray at
	// the files on berg; without it we embed placeholders the operator
	// must substitute locally (BYOK: the core never holds private keys).
	var certs []certificate
	var comment string
	if p.CertFile != "" {
		certs = []certificate{{
			CertificateFile: p.CertFile,
			KeyFile:         p.KeyFile,
		}}
	} else {
		certs = []certificate{{
			Certificate: []string{CertPlaceholder},
			Key:         []string{KeyPlaceholder},
		}}
		comment = "Substitute " + CertPlaceholder + " and " + KeyPlaceholder +
			" with real PEM cert/key content on berg before starting xray " +
			"(BYOK: the core never holds TLS private keys)."
	}
	cfg := serverConfig{
		Comment: comment,
		Log:     &logCfg{LogLevel: "warning"},
		Inbounds: []serverInbound{{
			Listen:   "0.0.0.0",
			Port:     h.ListenPort,
			Protocol: "vless",
			Settings: serverSettings{
				Clients:    []vlessClient{{ID: p.UUID, Flow: ""}},
				Decryption: "none",
			},
			StreamSettings: streamSettings{
				Network:  "tcp",
				Security: "tls",
				TLSSettings: &tlsSettings{
					ServerName:    p.SNI,
					AllowInsecure: p.AllowInsecure,
					Certificates:  certs,
				},
				TCPSettings: &tcpSettings{Header: &tcpHeader{Type: "none"}},
			},
			Tag: "vless-in",
		}},
		Outbounds: []outbound{{
			Protocol: "freedom",
			Tag:      "direct",
			Settings: freedomSettings{},
		}},
	}
	return marshal(cfg)
}

// RenderProxerConfig renders the owner-side note. The proxer runs
// nothing for this transport: berg dials the services directly at
// proxer_endpoint, so there is no tunnel client to install.
func (x *Xray) RenderProxerConfig(h store.Host) ([]byte, error) {
	p, err := ParseXrayParams(h.Params)
	if err != nil {
		return nil, err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# dyatel host %s - transport xray-vless\n\n", h.Name)
	b.WriteString("Nothing to run on this side (proxer).\n")
	fmt.Fprintf(&b, "The berg core terminates the VLESS+TLS leg and dials your services\ndirectly at %s:<target_port> for each forward.\n", p.ProxerEndpoint)
	b.WriteString("Expose the forwarded service ports on your public interface as usual;\nno tunnel client, no extra config.\n")
	return []byte(b.String()), nil
}

// RenderClientConfig renders the consumer-side xray JSON: one
// dokodemo-door inbound per forward on 127.0.0.1:public_port
// (destination = proxer_endpoint:target_port) routed into the single
// vless outbound toward berg.
func (x *Xray) RenderClientConfig(h store.Host, forwards []store.Forward) ([]byte, error) {
	p, err := ParseXrayParams(h.Params)
	if err != nil {
		return nil, err
	}
	inbounds := make([]clientInbound, 0, len(forwards))
	rules := make([]routingRule, 0, len(forwards))
	for _, f := range forwards {
		tag := fmt.Sprintf("fwd-%d", f.PublicPort)
		inbounds = append(inbounds, clientInbound{
			Listen:   "127.0.0.1",
			Port:     f.PublicPort,
			Protocol: "dokodemo-door",
			Settings: dokodemoSettings{
				Address:        p.proxerHost(),
				Port:           f.TargetPort,
				Network:        f.Proto,
				FollowRedirect: false,
			},
			Tag: tag,
		})
		rules = append(rules, routingRule{
			Type:        "field",
			InboundTag:  []string{tag},
			OutboundTag: "vless",
		})
	}
	cfg := clientConfig{
		Log:      &logCfg{LogLevel: "warning"},
		Inbounds: inbounds,
		Outbounds: []outbound{{
			Protocol: "vless",
			Tag:      "vless",
			Settings: vlessOutboundSettings{
				Vnext: []vnextServer{{
					Address: x.cfg.PublicEndpointHost,
					Port:    h.ListenPort,
					Users: []vlessUser{{
						ID:         p.UUID,
						Flow:       "",
						Security:   "auto",
						Encryption: "none",
					}},
				}},
			},
			StreamSettings: &streamSettings{
				Network:  "tcp",
				Security: "tls",
				TLSSettings: &tlsSettings{
					ServerName:    p.SNI,
					AllowInsecure: p.AllowInsecure,
				},
				TCPSettings: &tcpSettings{Header: &tcpHeader{Type: "none"}},
			},
		}, {
			Protocol: "freedom",
			Tag:      "direct",
			Settings: freedomSettings{},
		}},
		Routing: routing{Rules: rules},
	}
	return marshal(cfg)
}

func marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
