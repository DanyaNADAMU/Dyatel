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
	Name       string              `json:"name"`
	Interface  string              `json:"interface"`
	State      string              `json:"state"`
	ListenPort int                 `json:"listen_port"`
	Transport  string              `json:"transport"`
	Endpoints  map[string]Endpoint `json:"endpoints"`
	Drift      bool                `json:"drift"`
	LastError  string              `json:"last_error,omitempty"`
}

type Endpoint struct {
	PublicKey     string `json:"public_key"`
	Endpoint      string `json:"endpoint,omitempty"`
	LastHandshake string `json:"last_handshake,omitempty"`
	TransferRx    int64  `json:"transfer_rx,omitempty"`
	TransferTx    int64  `json:"transfer_tx,omitempty"`
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
	// Only this node's hosts: other daemons own theirs (DYATEL_NODE).
	hosts, err := r.st.HostsByNode(ctx, r.cfg.Node)
	if err != nil {
		r.lastErr(fmt.Errorf("load hosts: %w", err))
		return
	}
	seen := map[string]bool{}      // live ifaces
	seenNames := map[string]bool{} // live host names (ufw comment key)
	statuses := map[string]HostStatus{}
	for _, h := range hosts {
		ifname := wireguard.InterfaceName(h)
		tool := wireguard.ToolName(h.Transport) // wg / awg (awg = wg fork)
		linkType := wireguard.LinkType(h.Transport)
		st := HostStatus{Name: h.Name, Interface: ifname, State: h.State,
			ListenPort: h.ListenPort, Transport: h.Transport, Endpoints: map[string]Endpoint{}}
		cfg, err := r.wg.RenderGWConfig(h)
		if err != nil {
			st.LastError = err.Error()
			statuses[ifname] = st
			continue
		}
		if cfg == nil { // suspended: teardown iface, forwards pruned as orphan
			if out, err := run(ctx, tool, "show", ifname); err == nil && out != "" {
				stopAWGUnit(ctx, ifname)                        // userspace owner first, tun dies with it
				_, _ = run(ctx, "ip", "link", "delete", ifname) // teardown suspended
			}
			statuses[ifname] = st
			continue
		}
		seen[ifname] = true
		seenNames[h.Name] = true
		path := filepath.Join(filepath.Dir(r.cfg.WGConfigPath), ifname+".conf")
		if err := writeFileAtomic(path, cfg, 0600); err != nil {
			st.LastError = err.Error()
			statuses[ifname] = st
			continue
		}
		if _, err := run(ctx, "ip", "link", "show", ifname); err != nil {
			if err := r.bringUp(ctx, ifname, tool, linkType, path); err != nil {
				st.LastError = fmt.Sprintf("bring-up: %v", err)
			}
		} else if _, err := run(ctx, "bash", "-c",
			fmt.Sprintf("%s syncconf %s <(wg-quick strip %s) && ip link set %s up",
				tool, ifname, path, ifname)); err != nil {
			// syncconf keeps keys/peers without bouncing the tunnel; the
			// explicit link-up covers interfaces whose socket failed to bind
			// at creation (port conflict) and were left DOWN.
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
	r.pruneOrphans(ctx, seen, seenNames)
	r.mu.Lock()
	r.last, r.lastAt = statuses, time.Now()
	r.mu.Unlock()
}

// pruneOrphans removes NAT chains and UFW rules of hosts that no longer
// exist (or are suspended): iptables -S lists every DYATEL-<ifname> chain,
// ufw status lists every "Dyatel host=<name>" rule comment.
func (r *Reconciler) pruneOrphans(ctx context.Context, seen map[string]bool, seenNames map[string]bool) {
	// orphan wgd-*/awd-* interfaces (host deleted): bring the list down.
	// amneziawg registers its own link kind, so both families are scanned.
	for _, typ := range []struct{ link, prefix string }{
		{"wireguard", "wgd-"}, {"amneziawg", "awd-"},
	} {
		out, err := run(ctx, "ip", "-o", "link", "show", "type", typ.link)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(out, "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 || !strings.HasPrefix(fields[1], typ.prefix) {
				continue
			}
			iface := strings.TrimSuffix(fields[1], ":")
			if !seen[iface] {
				_, _ = run(ctx, "ip", "link", "delete", iface)
			}
		}
	}
	if out, err := run(ctx, "iptables", "-t", "nat", "-S"); err == nil {
		for _, line := range strings.Split(out, "\n") {
			if !strings.HasPrefix(line, "-N DYATEL-") {
				continue
			}
			chain := strings.TrimPrefix(line, "-N ")
			iface := strings.TrimSuffix(strings.TrimPrefix(chain, "DYATEL-"), "-po")
			if seen[iface] {
				continue
			}
			for { // drop jumps from both nat hooks, then the chain
				gone := true
				for _, h := range []string{"PREROUTING", "POSTROUTING"} {
					if _, err := run(ctx, "iptables", "-t", "nat", "-D", h, "-j", chain); err == nil {
						gone = false
					}
				}
				if gone {
					break
				}
			}
			_, _ = run(ctx, "iptables", "-t", "nat", "-F", chain)
			_, _ = run(ctx, "iptables", "-t", "nat", "-X", chain)
		}
	}
	if out, err := run(ctx, r.cfg.UFWBinary, "status"); err == nil {
		for _, line := range strings.Split(out, "\n") {
			const mark = "# Dyatel host="
			i := strings.Index(line, mark)
			if i < 0 {
				continue
			}
			fields := strings.Fields(line[:i])
			if len(fields) == 0 || seenNames[strings.TrimSpace(line[i+len(mark):])] {
				continue
			}
			_, _ = run(ctx, r.cfg.UFWBinary, "--force", "delete", "allow", fields[0])
		}
	}
}

// bringUp creates a transport interface for the first time. Kernel path is
// in-kernel syncconf; without the amneziawg kernel module (Debian 13 ships
// none) awd-* falls back to userspace amneziawg-go owning a tun_iface, mirroring
// the vendored awg-quick fallback. Userspace needs no addresses — utun is
// point-to-point and the interface lives only as long as the unit.
func (r *Reconciler) bringUp(ctx context.Context, ifname, tool, linkType, path string) error {
	if linkType == "wireguard" {
		_, err := run(ctx, "bash", "-c",
			fmt.Sprintf("ip link add %s type wireguard && %s setconf %s <(wg-quick strip %s) && ip addr add %s/32 dev %s && ip addr add %s/128 dev %s && ip link set %s up",
				ifname, tool, ifname, path, r.cfg.CoreListenIP, ifname, strings.TrimSuffix(r.gwV6(), ""), ifname, ifname))
		return err
	}
	// amneziawg: kernel module first, userspace fallback (awg-quick pattern)
	if _, err := run(ctx, "ip", "link", "add", ifname, "type", "amneziawg"); err == nil {
		_, err := run(ctx, "bash", "-c",
			fmt.Sprintf("%s setconf %s <(wg-quick strip %s) && ip addr add %s/32 dev %s && ip addr add %s/128 dev %s && ip link set %s up",
				tool, ifname, path, r.cfg.CoreListenIP, ifname, strings.TrimSuffix(r.gwV6(), ""), ifname, ifname))
		return err
	}
	// No kernel module: transient unit starts userspace amneziawg-go owning
	// the tun (vendored awg-quick pattern: binary takes the tun name as argv).
	// amneziawg-go daemonizes (forks into the background), so the unit's
	// main process exits immediately: Type=forking tells systemd to adopt
	// the forked child as the main PID. Without it the unit deactivates on
	// parent exit and KillMode=control-group kills the daemon, losing the
	// tun. Supervision comes from the reconcile pass instead: if the daemon
	// dies, its tun disappears and the next pass re-runs this unit.
	if out, err := run(ctx, "systemctl", "is-active", awgUnitName(ifname)); err != nil || strings.TrimSpace(out) != "active" {
		if _, err := run(ctx, "systemd-run", "--unit", awgUnitName(ifname),
			"--property", "Type=forking",
			"/usr/local/bin/amneziawg-go", ifname); err != nil {
			return fmt.Errorf("userspace fallback: %w", err)
		}
	}
	// wait for the tun to appear so syncconf/addr on it can't race the daemon
	for i := 0; i < 50; i++ {
		if _, err := run(ctx, "ip", "link", "show", ifname); err == nil {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	_, err := run(ctx, "bash", "-c",
		fmt.Sprintf("%s syncconf %s <(wg-quick strip %s) && ip addr add %s/32 dev %s && ip addr add %s/128 dev %s && ip link set %s up",
			tool, ifname, path, r.cfg.CoreListenIP, ifname, strings.TrimSuffix(r.gwV6(), ""), ifname, ifname))
	return err
}

// stopAWGUnit stops the transient userspace unit if it is running this iface.
func stopAWGUnit(ctx context.Context, ifname string) {
	_, _ = run(ctx, "systemctl", "stop", awgUnitName(ifname))
}

func awgUnitName(ifname string) string { return "dyatel-awg-" + ifname }

func (r *Reconciler) Status(ctx context.Context) map[string]any {
	hosts, err := r.st.HostsByNode(ctx, r.cfg.Node)
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	out := map[string]any{}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, h := range hosts {
		ifname := wireguard.InterfaceName(h)
		st := r.last[ifname]
		// live handshake data from wg/awg show
		if st.State == "active" {
			if show, err := run(ctx, wireguard.ToolName(h.Transport), "show", ifname, "dump"); err == nil {
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
	// src-NAT chain hangs off POSTROUTING (see the MASQUERADE rule below).
	poChain := "DYATEL-" + ifname + "-po"
	// per-iface nat chains, flushed and refilled each pass (idempotent, no-bounce
	// for established flows — conntrack survives the same-rule rewrite)
	for _, c := range []string{natChain, poChain} {
		_, _ = run(ctx, "iptables", "-t", "nat", "-N", c)
		_, _ = run(ctx, "iptables", "-t", "nat", "-F", c)
	}
	// src-NAT chain: forwarded packets keep the client's internet source
	// IP after DNAT, which the host's wg cryptokey routing (AllowedIPs =
	// gw /32 only) silently drops. MASQUERADE rewrites them to the gw
	// tunnel IP; un-NAT on the way back rides conntrack. Match on the
	// post-DNAT destination (-d): in POSTROUTING the conntrack original
	// direction still carries the public IP (DNAT ran in PREROUTING), so
	// --ctorigdst never matches, and --ctstatus DNAT is rejected by
	// iptables-nft 1.8.9 ("Bad ctstatus").
	_, _ = run(ctx, "iptables", "-t", "nat", "-A", poChain,
		"-o", ifname, "-d", tv+"/32", "-j", "MASQUERADE")
	want := map[string]bool{} // "port/proto" keys this host must expose
	// Transport listen port is runtime state, so the core — not Ansible —
	// owns its firewall opening (same want/prune cycle as forwards).
	if h.Transport == "wireguard" || h.Transport == "amneziawg" {
		key := fmt.Sprintf("%d/udp", h.ListenPort)
		want[key] = true
		_, _ = run(ctx, r.cfg.UFWBinary, "allow", key,
			"comment", "Dyatel host="+h.Name)
	}
	for _, f := range fwds {
		key := fmt.Sprintf("%d/%s", f.PublicPort, f.Proto)
		want[key] = true
		// `ufw allow` skips existing rules: safe to re-add every pass.
		// no shell => no quoting; ufw rejects comment args
		// containing literal quotes ("Invalid syntax")
		_, _ = run(ctx, r.cfg.UFWBinary, "allow", key,
			"comment", "Dyatel host="+h.Name)
		_, _ = run(ctx, "iptables", "-t", "nat", "-A", natChain,
			"-p", f.Proto, "--dport", fmt.Sprint(f.PublicPort),
			"-j", "DNAT", "--to-destination", fmt.Sprintf("%s:%d", tv, f.TargetPort))
	}
	// drop stale ufw rules this host no longer wants (deleted forwards)
	if out, _ := run(ctx, r.cfg.UFWBinary, "status"); out != "" {
		for _, line := range strings.Split(out, "\n") {
			if !strings.Contains(line, "# Dyatel host="+h.Name+"") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) == 0 || want[fields[0]] {
				continue
			}
			_, _ = run(ctx, r.cfg.UFWBinary, "--force", "delete", "allow", fields[0])
		}
	}
	// exactly one jump per chain: `iptables -C` reports via exit status
	// only (stdout is empty), so err — not output — is the signal.
	hook := func(c string) string {
		if c == natChain {
			return "PREROUTING"
		}
		return "POSTROUTING"
	}
	for _, c := range []string{natChain, poChain} {
		h := hook(c)
		for {
			if _, err := run(ctx, "iptables", "-t", "nat", "-C", h, "-j", c); err != nil {
				break // no (more) jumps
			}
			if _, err := run(ctx, "iptables", "-t", "nat", "-D", h, "-j", c); err != nil {
				break
			}
		}
		if _, err := run(ctx, "iptables", "-t", "nat", "-C", h, "-j", c); err != nil {
			_, _ = run(ctx, "iptables", "-t", "nat", "-I", h, "-j", c)
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
	// wg clamps before deriving the public key, like wireguard-tools does.
	priv[0] &= 248
	priv[31] &= 7
	priv[31] |= 64
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return "", "", err
	}
	// wg clamps (b[31] = (b[31] & 127) | 64) — the stored private key must
	// stay bit-identical to the one the public key was derived from.
	priv[31] &= 127
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
