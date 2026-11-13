package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"

	"nadamu/dyatel/internal/config"
	"nadamu/dyatel/internal/store"
	"nadamu/dyatel/internal/transport/wireguard"
	"nadamu/dyatel/internal/transport/xrayvless"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

// gen: offline config rendering, the Tier-0 path of the panel-less model.
// The pure renderers live in the transport packages and take a plain
// store.Host — no store, no daemon, no database. gen is just a driver:
// it builds the Host from flags, calls the renderers, prints or writes.
// A proxer can deploy themselves with the ansible playbook plus this
// command alone; PG, Authentik and the daemon are convenience, not a
// requirement.

var genCmd = &cobra.Command{
	Use:   "gen",
	Short: "Render host configs offline (no daemon, no database)",
	Long: "gen renders proxer/berg/client configs from flags alone.\n\n" +
		"It never contacts the daemon: the renderers are pure functions\n" +
		"over a store.Host struct, so PG, Authentik and the daemon are a\n" +
		"convenience (Tier 1), not a requirement (Tier 0 = playbook + gen).",
	SilenceErrors: true,
	SilenceUsage:  true,
}

var genWGCmd = &cobra.Command{
	Use:   "wireguard",
	Short: "Render wireguard/amneziawg configs for one host",
	RunE:  runGenWG,
}

var genXrayCmd = &cobra.Command{
	Use:   "xray",
	Short: "Render xray-vless configs for one host",
	RunE:  runGenXray,
}

func init() {
	for _, sub := range []*cobra.Command{genWGCmd, genXrayCmd} {
		f := sub.Flags()
		f.String("name", "", "host name (a-z0-9-, required)")
		f.String("transport", "", "transport: wireguard or amneziawg (wireguard cmd only)")
		f.Int("port", 0, "berg listen port (default: first pool port for the transport)")
		f.String("endpoint", "", "public endpoint host clients dial (default: DYATEL_ENDPOINT or localhost)")
		f.String("listen-ip", "", "berg tunnel IP (default: first host of DYATEL_TUNNEL_V4)")
		f.String("tunnel4", "", "proxer tunnel IPv4/32 (default: next free in DYATEL_TUNNEL_V4 after listen-ip)")
		f.String("tunnel6", "", "proxer tunnel IPv6/128 (default: derived from DYATEL_TUNNEL_V6)")
		f.String("client-tunnel4", "", "consumer tunnel IPv4 (default: proxer IP +1)")
		f.String("client-tunnel6", "", "consumer tunnel IPv6 (default: proxer IP +1)")
		f.String("client-pubkey", "", "consumer wg public key (BYOK, client config only)")
		f.String("proxer-pubkey", "", "proxer wg public key (BYOK; adds the proxer peer to the berg config)")
		f.String("params", "{}", "transport params JSON (amneziawg junk header)")
		f.String("psk", "", "preshared key (default: generate fresh)")
		f.String("gw-priv", "", "berg gw private key (default: generate fresh)")
		f.String("sni", "", "xray: TLS SNI (default: endpoint)")
		f.String("uuid", "", "xray: vless user UUID (default: generate fresh)")
		f.String("proxer-endpoint", "", "xray: proxer service host berg dials (default: endpoint)")
		f.String("mode", "", "xray: masquerade mode, tls or nginx (default: tls)")
		f.String("ws-path", "", "xray: nginx-mode masquerade websocket path (required in nginx mode)")
		f.Int("public-port", 0, "xray: nginx-mode public vhost TLS port (default: 443)")
		f.String("fallback", "", "xray: tls-mode fallback dest host:port for non-vless probes (optional)")
		f.String("forwards", "", "xray: forwards spec public:target[:proto][,...]")
		genCmd.AddCommand(sub)
	}
	rootCmd.AddCommand(genCmd)
}

// genConfig loads env-driven settings without touching the database:
// LoadForRender reads only DYATEL_* env vars and never requires the DSN.
func genConfig() *config.Config {
	return config.LoadForRender()
}

func genHost(cmd *cobra.Command) (store.Host, *config.Config, error) {
	f := cmd.Flags()
	name, _ := f.GetString("name")
	if name == "" {
		return store.Host{}, nil, fmt.Errorf("--name is required")
	}
	c := genConfig()

	transport := "wireguard"
	if cmd.Name() == "xray" {
		transport = "xray-vless"
	} else if v, _ := f.GetString("transport"); v != "" {
		if v != "wireguard" && v != "amneziawg" {
			return store.Host{}, nil, fmt.Errorf("--transport must be wireguard or amneziawg")
		}
		transport = v
	}

	port, _ := f.GetInt("port")
	if port == 0 {
		switch transport {
		case "amneziawg":
			port = c.PortPoolAWGMin
		case "xray-vless":
			port = c.PortPoolXrayMin
		default:
			port = c.PortPoolWGMin
		}
	}

	endpoint, _ := f.GetString("endpoint")
	if endpoint == "" {
		endpoint = c.PublicEndpointHost
	}

	// Berg tunnel IP: default first usable host of the net.
	listenIP, _ := f.GetString("listen-ip")
	if listenIP == "" {
		listenIP = c.CoreListenIP
	}

	// Proxer tunnel defaults skip berg's own address: the daemon allocates
	// from the same nets but never hands out CoreListenIP, so gen must not
	// either — a colliding /32 breaks routing both sides.
	t4, _ := f.GetString("tunnel4")
	if t4 == "" {
		ip := nextIP(net.ParseIP(strings.Split(c.TunnelIPv4Net, "/")[0]).To4(), 1)
		if ip.String() == c.CoreListenIP {
			ip = nextIP(ip, 1)
		}
		t4 = ip.String() + "/32"
	}
	t6, _ := f.GetString("tunnel6")
	if t6 == "" {
		ip := nextIP(net.ParseIP(strings.Split(c.TunnelIPv6Net, "/")[0]), 1)
		if ip.String() == gwIPv6Base(c) {
			ip = nextIP(ip, 1)
		}
		t6 = ip.String() + "/128"
	}

	psk, _ := f.GetString("psk")
	if psk == "" {
		p, err := wireguard.GeneratePSK()
		if err != nil {
			return store.Host{}, nil, err
		}
		psk = p
	}
	gwPriv, _ := f.GetString("gw-priv")
	var gwPub string
	if gwPriv == "" {
		// GenerateKeypair returns (priv, pub); gen needs both.
		priv, pub, err := wireguard.GenerateKeypair()
		if err != nil {
			return store.Host{}, nil, err
		}
		gwPriv, gwPub = priv, pub
	}

	params := []byte("{}")
	if raw, _ := f.GetString("params"); raw != "" {
		params = []byte(raw)
	}

	keepalive := 25

	h := store.Host{
		ID:             uuid.New(),
		Name:           name,
		Node:           c.Node,
		OwnerID:        uuid.Nil,
		ConsumerID:     uuid.Nil,
		WGPreSharedKey: psk,
		GWPrivateKey:   gwPriv,
		GWPublicKey:    gwPub,
		TunnelIPv4:     t4,
		TunnelIPv6:     t6,
		Transport:      transport,
		ListenPort:     port,
		Params:         params,
		Keepalive:      keepalive,
		State:          "active",
	}

	// Consumer side: BYOK public key + tunnel IPs (client config only).
	if ck, _ := f.GetString("client-pubkey"); ck != "" {
		ct4, _ := f.GetString("client-tunnel4")
		ct6, _ := f.GetString("client-tunnel6")
		if ct4 == "" {
			ct4 = nextIP(net.ParseIP(strings.TrimSuffix(t4, "/32")).To4(), 1).String()
		}
		if ct6 == "" {
			ct6 = nextIP(net.ParseIP(strings.TrimSuffix(t6, "/128")), 1).String()
		}
		h.ConsumerWGPublicKey = &ck
		h.ConsumerTunnelIPv4 = &ct4
		h.ConsumerTunnelIPv6 = &ct6
	}
	// Proxer BYOK key: registered out-of-band (no daemon here), it only
	// decides whether the berg config carries a proxer peer at all.
	if pk, _ := f.GetString("proxer-pubkey"); pk != "" {
		h.WGPublicKey = pk
	}
	return h, c, nil
}

// gwIPv6Base mirrors the renderer's gwIPv6: berg's v6 is the net base +1.
func gwIPv6Base(c *config.Config) string {
	return nextIP(net.ParseIP(strings.Split(c.TunnelIPv6Net, "/")[0]), 1).String()
}

// nextIP returns ip advanced by n (1 = next address).
func nextIP(ip net.IP, n int) net.IP {
	if ip == nil {
		return net.IPv4(10, 13, 36, 2)
	}
	out := make(net.IP, len(ip))
	copy(out, ip)
	for i := len(out) - 1; i >= 0 && n > 0; i-- {
		v := int(out[i]) + n
		out[i] = byte(v)
		n = v >> 8
	}
	return out
}

func runGenWG(cmd *cobra.Command, args []string) error {
	h, c, err := genHost(cmd)
	if err != nil {
		return err
	}
	wg := wireguard.New(c)

	gwCfg, err := wg.RenderGWConfig(h)
	if err != nil {
		return fmt.Errorf("berg config: %w", err)
	}
	proxerCfg, err := wg.RenderProxerConfig(h)
	if err != nil {
		return fmt.Errorf("proxer config: %w", err)
	}
	proxerCfg = []byte(strings.Replace(string(proxerCfg),
		"PrivateKey = "+wireguard.PrivateKeyPlaceholder,
		"PrivateKey = <fill-proxer-private-key-here>", 1))

	var clientCfg []byte
	if h.ConsumerWGPublicKey != nil {
		clientCfg, err = wg.RenderClientConfig(h)
		if err != nil {
			return fmt.Errorf("client config: %w", err)
		}
		clientCfg = []byte(strings.Replace(string(clientCfg),
			"PrivateKey = "+wireguard.PrivateKeyPlaceholder,
			"PrivateKey = <fill-client-private-key-here>", 1))
	}

	printGenOut(cmd, "berg (gw) config", gwCfg)
	printGenOut(cmd, "proxer config", proxerCfg)
	if clientCfg != nil {
		printGenOut(cmd, "client config", clientCfg)
	} else {
		fmt.Fprintln(cmd.OutOrStdout(), "# client config: register a consumer BYOK key (--client-pubkey) to render it")
	}
	fmt.Fprintf(cmd.OutOrStdout(), "# berg gw private key (generated): %s\n", h.GWPrivateKey)
	fmt.Fprintf(cmd.OutOrStdout(), "# psk (generated): %s\n", h.WGPreSharedKey)
	return nil
}

func runGenXray(cmd *cobra.Command, args []string) error {
	h, c, err := genHost(cmd)
	if err != nil {
		return err
	}
	f := cmd.Flags()

	// xray params come from the same --params JSON plus the xray-specific
	// flags: uuid (generate), sni/proxer endpoint (default endpoint).
	p := map[string]any{}
	if err := json.Unmarshal(h.Params, &p); err != nil {
		return fmt.Errorf("--params: %w", err)
	}
	id, _ := f.GetString("uuid")
	if id == "" {
		id = uuid.New().String()
	}
	p["uuid"] = id
	sni, _ := f.GetString("sni")
	if sni == "" {
		sni, _ = f.GetString("endpoint")
		if sni == "" {
			sni = c.PublicEndpointHost
		}
	}
	p["sni"] = sni
	pe, _ := f.GetString("proxer-endpoint")
	if pe == "" {
		pe = sni
	}
	p["proxer_endpoint"] = pe
	if mode, _ := f.GetString("mode"); mode != "" {
		p["mode"] = mode
	}
	if wp, _ := f.GetString("ws-path"); wp != "" {
		p["ws_path"] = wp
	}
	if pp, _ := f.GetInt("public-port"); pp != 0 {
		p["public_port"] = pp
	}
	if fb, _ := f.GetString("fallback"); fb != "" {
		p["fallback"] = fb
	}
	h.Params, err = json.Marshal(p)
	if err != nil {
		return err
	}

	xr := xrayvless.New(c)

	srvCfg, err := xr.RenderServerConfig(h)
	if err != nil {
		return fmt.Errorf("berg config: %w", err)
	}
	proxerCfg, err := xr.RenderProxerConfig(h)
	if err != nil {
		return fmt.Errorf("proxer config: %w", err)
	}

	forwards := []store.Forward{}
	spec, _ := f.GetString("forwards")
	if spec != "" {
		for i, part := range strings.Split(spec, ",") {
			fields := strings.Split(part, ":")
			if len(fields) < 2 {
				return fmt.Errorf("forward %d: want public:target[:proto]", i+1)
			}
			var pub, tgt int
			if _, err := fmt.Sscanf(fields[0]+":"+fields[1], "%d:%d", &pub, &tgt); err != nil {
				return fmt.Errorf("forward %d: %w", i+1, err)
			}
			proto := "tcp"
			if len(fields) > 2 {
				proto = fields[2]
			}
			forwards = append(forwards, store.Forward{
				ID:         uuid.New(),
				HostID:     h.ID,
				PublicPort: pub,
				TargetPort: tgt,
				Proto:      proto,
			})
		}
	}
	clientCfg, err := xr.RenderClientConfig(h, forwards)
	if err != nil {
		return fmt.Errorf("client config: %w", err)
	}

	printGenOut(cmd, "berg (server) config", srvCfg)
	printGenOut(cmd, "proxer note", proxerCfg)
	printGenOut(cmd, "client config", clientCfg)
	fmt.Fprintf(cmd.OutOrStdout(), "# vless uuid (generated): %s\n", id)
	return nil
}

// printGenOut writes one rendered config with a header; JSON pretty when
// it parses (xray), raw otherwise (wg-quick).
func printGenOut(cmd *cobra.Command, title string, cfg []byte) {
	w := cmd.OutOrStdout()
	fmt.Fprintf(w, "\n=== %s ===\n", title)
	var pretty map[string]any
	if err := json.Unmarshal(cfg, &pretty); err == nil {
		b, _ := json.MarshalIndent(pretty, "", "  ")
		fmt.Fprintln(w, string(b))
		return
	}
	fmt.Fprintln(w, string(cfg))
}

var _ = os.Exit
