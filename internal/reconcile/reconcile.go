package reconcile

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/curve25519"
	"nadamu/dyatel/internal/config"
	"nadamu/dyatel/internal/store"
	"nadamu/dyatel/internal/transport/wireguard"
)

type Reconciler struct {
	cfg    *config.Config
	st     *store.Store
	wg     *wireguard.WG
	kick   chan struct{}
	mu     sync.Mutex
	last   map[string]HostStatus // ifname -> status
	lastAt time.Time
}

type HostStatus struct {
	Name           string    `json:"name"`
	Interface       string    `json:"interface"`
	State          string    `json:"state"`
	ListenPort      int       `json:"listen_port"`
	Transport       string    `json:"transport"`
	Endpoints       map[string]Endpoint `json:"endpoints"`
	Drift           bool      `json:"drift"`
	LastError       string    `json:"last_error,omitempty"`
}

type Endpoint struct {
	PublicKey      string `json:"public_key"`
	Endpoint       string `json:"endpoint,omitempty"`
	LastHandshake   string `json:"last_handshake,omitempty"`
	TransferRx      int64  `json:"transfer_rx,omitempty"`
	TransferTx      int64  `json:"transfer_tx,omitempty"`
}

func New(cfg *config.Config, st *store.Store) *Reconciler {
	return &Reconciler{cfg: cfg, st: st, wg: wireguard.New(cfg),
		kick: make(chan struct{}, 1), last: map[string]HostStatus{}}
}

// Trigger asks for an out-of-band reconcile pass (API mutation → loop picks it up).
func (r *Reconciler) Trigger() {
	select {
	case r.kick <- struct{}{}:
	default:
	}
}

// PrepareHost generates the core-side material (PSK + berg keypair) and
// persists the host. BYOK (RFC §3.4b): user private keys never touch the core.
func (r *Reconciler) PrepareHost(ctx context.Context, h *store.Host) error {
	psk, err := genPSK()
	if err != nil {
		return err
	}
	gwPriv, gwPub, err := genKeypair()
	if err != nil {
		return err
	}
	h.WGPreSharedKey = psk
	h.GWPrivateKey, h.GWPublicKey = gwPriv, gwPub
	if err := r.st.CreateHost(ctx, h); err != nil {
		return err
	}
	r.Trigger()
	return nil
}

// PrepareConsumer registers the consumer BYOK key and allocates their tunnel IPs.
func (r *Reconciler) PrepareConsumer(ctx context.Context, h *store.Host, pubKey, tv4, tv6 string) error {
	_, err := r.st.Pool.Exec(ctx,
		`UPDATE hosts SET consumer_wg_public_key=$2, consumer_tunnel_ipv4=$3,
		   consumer_tunnel_ipv6=$4, updated_at=now()
		 WHERE id=$1`, h.ID, pubKey, strings.TrimSuffix(tv4, "/32"), strings.TrimSuffix(tv6, "/128"))
	if err != nil {
		return err
	}
	h.ConsumerWGPublicKey = &pubKey
	h.ConsumerTunnelIPv4, h.ConsumerTunnelIPv6 = &tv4, &tv6
	return nil
}

// Run blocks until ctx is done, reconciling every tick or on Trigger.
func (r *Reconciler) Run(ctx context.Context) {
	d := time.Duration(r.cfg.ReconcileEverySec) * time.Second
	t := time.NewTicker(d)
	defer t.Stop()
	for {
		r.pass(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-r.kick:
		}
	}
}

// pass renders desired state for all hosts and applies it (no-bounce).
func (r *Reconciler) pass(ctx context.Context) {
	hosts, err := r.st.Hosts(ctx)
	if err != nil {
		r.lastErr(fmt.Errorf("load hosts: %w", err))
		return
	}
	seen := map[string]bool{}
	statuses := map[string]HostStatus{}
	for _, h := range hosts {
		ifname := wireguard.InterfaceName(h)
		seen[ifname] = true
		st := HostStatus{Name: h.Name, Interface: ifname, State: h.State,
			ListenPort: h.ListenPort, Transport: h.Transport, Endpoints: map[string]Endpoint{}}
		cfg, err := r.wg.RenderGWConfig(h)
		if err != nil {
			st.LastError = err.Error()
			statuses[ifname] = st
			continue
		}
		if cfg == nil { // suspended
			if out, err := run(ctx, "wg", "show", ifname); err == nil && out != "" {
				_, _ = run(ctx, "ip", "link", "delete", ifname) // teardown suspended
			}
			statuses[ifname] = st
			continue
		}
		path := filepath.Join(filepath.Dir(r.cfg.WGConfigPath), ifname+".conf")
		if err := writeFileAtomic(path, cfg, 0600); err != nil {
			st.LastError = err.Error()
			statuses[ifname] = st
			continue
		}
		if _, err := run(ctx, "ip", "link", "show", ifname); err != nil {
			// interface missing → first bring-up
			if _, err := run(ctx, "bash", "-c",
				fmt.Sprintf("ip link add %s type wireguard && wg setconf %s <(wg-quick strip %s) && ip addr add %s/32 dev %s && ip addr add %s/128 dev %s && ip link set %s up",
					ifname, ifname, path, r.cfg.CoreListenIP, ifname, strings.TrimSuffix(r.gwV6(), ""), ifname, ifname)); err != nil {
				st.LastError = fmt.Sprintf("bring-up: %v", err)
			}
		} else if _, err := run(ctx, "bash", "-c",
			fmt.Sprintf("wg syncconf %s <(wg-quick strip %s)", ifname, path)); err != nil {
			st.LastError = fmt.Sprintf("syncconf: %v", err)
		}
		// routes: proxer tunnel net reachable via this iface
		_, _ = run(ctx, "ip", "route", "replace",
			strings.TrimSuffix(h.TunnelIPv4, "/32")+"/32", "dev", ifname)
		st.Endpoints["proxer"] = Endpoint{PublicKey: h.WGPublicKey}
		if h.ConsumerWGPublicKey != nil {
			st.Endpoints["consumer"] = Endpoint{PublicKey: *h.ConsumerWGPublicKey}
		}
		// UFW + NAT for forwards
		fwds, err := r.st.ForwardsByHost(ctx, h.ID)
		if err == nil {
			r.applyForwards(ctx, ifname, h, fwds)
		}
		statuses[ifname] = st
	}
	r.mu.Lock()
	r.last, r.lastAt = statuses, time.Now()
	r.mu.Unlock()
}

func (r *Reconciler) Status(ctx context.Context) map[string]any {
	hosts, err := r.st.Hosts(ctx)
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	out := map[string]any{}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, h := range hosts {
		ifname := wireguard.InterfaceName(h)
		st := r.last[ifname]
		// live handshake data from wg show
		if st.State == "active" {
			if show, err := run(ctx, "wg", "show", ifname, "dump"); err == nil {
				parseDump(show, st.Endpoints)
			}
		}
		out[h.ID.String()] = st
	}
	out["_checked_at"] = r.lastAt
	return out
}

// applyForwards allows the public port in UFW and installs NAT to the proxer tunnel IP.
func (r *Reconciler) applyForwards(ctx context.Context, ifname string, h store.Host, fwds []store.Forward) {
	tv := strings.TrimSuffix(h.TunnelIPv4, "/32")
	natChain := "DYATEL-" + ifname
	// per-iface nat chain, flushed and refilled each pass (idempotent, no-bounce
	// for established flows — conntrack survives the same-rule rewrite)
	_, _ = run(ctx, "iptables", "-t", "nat", "-N", natChain)
	_, _ = run(ctx, "iptables", "-t", "nat", "-F", natChain)
	for _, f := range fwds {
		_, _ = run(ctx, r.cfg.UFWBinary, "allow", fmt.Sprintf("%d/%s", f.PublicPort, f.Proto),
			"comment", "'Dyatel host="+h.Name+"'")
		_, _ = run(ctx, "iptables", "-t", "nat", "-A", natChain,
			"-p", f.Proto, "--dport", fmt.Sprint(f.PublicPort),
			"-j", "DNAT", "--to-destination", fmt.Sprintf("%s:%d", tv, f.TargetPort))
	}
	// jump from PREROUTING (idempotent via -C check)
	if out, _ := run(ctx, "iptables", "-t", "nat", "-S", natChain); out != "" {
		chk, _ := run(ctx, "bash", "-c",
			fmt.Sprintf("iptables -t nat -C PREROUTING -j %s 2>/dev/null", natChain))
		if chk == "" {
			_, _ = run(ctx, "iptables", "-t", "nat", "-I", "PREROUTING", "-j", natChain)
		}
	}
}

func (r *Reconciler) gwV6() string {
	if _, cidr, err := parseCIDR(r.cfg.TunnelIPv6Net); err == nil {
		ip := make(net.IP, len(cidr.IP))
		copy(ip, cidr.IP)
		ip[len(ip)-1] = 1
		return ip.String()
	}
	return "fd00:36::1"
}

func (r *Reconciler) lastErr(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.last["_error"]
	_ = s
	r.last["_error"] = HostStatus{LastError: err.Error()}
}

// genPSK returns a base64 32-byte preshared key.
func genPSK() (string, error) {
	b := make([]byte, 32)
	if _, err := randRead(b); err != nil {
		return "", err
	}
	return base64Encode(b), nil
}

// genKeypair returns (base64 priv, base64 pub) for the berg-side wg interface.
func genKeypair() (string, string, error) {
	var priv [32]byte
	if _, err := randRead(priv[:]); err != nil {
		return "", "", err
	}
	pub, err := curve25519.X25519(priv[:], make([]byte, 32))
	if err != nil {
		return "", "", err
	}
	// wg clamps
	priv[0] &= 248
	priv[31] = 127
	priv[31] |= 64
	return base64Encode(priv[:]), base64Encode(pub[:]), nil
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func run(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var out strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return strings.TrimSpace(out.String()), err
}

// parseDump fills live endpoint info from `wg show <if> dump` (tab format).
func parseDump(dump string, eps map[string]Endpoint) {
	for _, line := range strings.Split(dump, "\n") {
		f := strings.Split(line, "\t")
		if len(f) < 6 {
			continue
		}
		for who, ep := range eps {
			if ep.PublicKey != f[0] {
				continue
			}
			ep.Endpoint = f[2]
			ep.LastHandshake = f[3]
			ep.TransferRx = atoi(f[4])
			ep.TransferTx = atoi(f[5])
			eps[who] = ep
		}
	}
}

func atoi(s string) int64 {
	var n int64
	fmt.Sscanf(s, "%d", &n)
	return n
}