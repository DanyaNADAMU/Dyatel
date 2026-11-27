package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
	"nadamu/dyatel/internal/config"
	"nadamu/dyatel/internal/dns"
	"nadamu/dyatel/internal/store"
)

func newTestReconciler(cfg *config.Config, fn cmdRunner) *Reconciler {
	r := New(cfg, nil)
	r.exec = fn
	return r
}

func testCfg(dir string) *config.Config {
	return &config.Config{
		TunnelIPv4NetWG:  "10.66.66.0/24",
		TunnelIPv6NetWG:  "fd66:66::/64",
		TunnelIPv4NetAWG: "10.77.77.0/24",
		TunnelIPv6NetAWG: "fd77:77::/64",
		WGConfigPath:     filepath.Join(dir, "wg-dyatel.conf"),
		UFWBinary:        "/usr/sbin/ufw",
	}
}

func TestTransportFromIfnameAndUnitName(t *testing.T) {
	cases := []struct {
		ifname string
		want   string
		ok     bool
	}{
		{"wgd-mc", "wireguard", true},
		{"awd-mc", "amneziawg", true},
		{"wg-dyatel", "", false},
	}
	for _, tc := range cases {
		got, ok := transportFromIfname(tc.ifname)
		if got != tc.want || ok != tc.ok {
			t.Fatalf("transportFromIfname(%q) = (%q, %v), want (%q, %v)", tc.ifname, got, ok, tc.want, tc.ok)
		}
	}
	if got := awgUnitName("awd-mc"); got != "dyatel-awg-awd-mc" {
		t.Fatalf("awgUnitName = %q", got)
	}
}

func TestParseDump(t *testing.T) {
	eps := map[string]Endpoint{
		"proxer":   {PublicKey: "pk1"},
		"consumer": {PublicKey: "pk2"},
	}
	dump := "gwpriv\tgwpub\t51820\toff\n" +
		"pk1\tpsk\t1.2.3.4:5555\t10.66.66.2/32,fd66:66::2/128\t1700000000\t120\t340\t25\n" +
		"pk2\tpsk\t(none)\t10.66.66.3/32,fd66:66::3/128\t0\t0\t0\toff\n"
	parseDump(dump, eps)

	if eps["proxer"].Endpoint != "1.2.3.4:5555" || eps["proxer"].LastHandshake != "1700000000" ||
		eps["proxer"].TransferRx != 120 || eps["proxer"].TransferTx != 340 {
		t.Fatalf("unexpected proxer endpoint: %+v", eps["proxer"])
	}
	if eps["consumer"].Endpoint != "(none)" || eps["consumer"].LastHandshake != "0" ||
		eps["consumer"].TransferRx != 0 || eps["consumer"].TransferTx != 0 {
		t.Fatalf("unexpected consumer handshake: %+v", eps["consumer"])
	}
}

func TestEnsureGatewayAddrsConvergesStaleAddrs(t *testing.T) {
	var calls []string
	r := newTestReconciler(testCfg(t.TempDir()), func(_ context.Context, name string, args ...string) (string, error) {
		line := name + " " + strings.Join(args, " ")
		calls = append(calls, line)
		if name == "ip" && len(args) >= 3 && args[0] == "-4" && args[1] == "-o" {
			return "5: awd-tiny inet 10.13.36.1/32 scope global awd-tiny\n5: awd-tiny inet 10.77.77.1/32 scope global awd-tiny", nil
		}
		if name == "ip" && len(args) >= 3 && args[0] == "-6" && args[1] == "-o" {
			return "5: awd-tiny inet6 fe80::1/64 scope link\n5: awd-tiny inet6 fd00:36::1/128 scope global", nil
		}
		return "", nil
	})

	r.ensureGatewayAddrs(context.Background(), "awd-tiny", "amneziawg")

	wantCalls := []string{
		"ip addr del 10.13.36.1/32 dev awd-tiny",
		"ip addr replace 10.77.77.1/32 dev awd-tiny",
		"ip addr del fd00:36::1/128 dev awd-tiny",
		"ip addr replace fd77:77::1/128 dev awd-tiny",
	}
	for _, want := range wantCalls {
		if !slices.Contains(calls, want) {
			t.Fatalf("missing call %q in %v", want, calls)
		}
	}
	if slices.Contains(calls, "ip addr del fe80::1/64 dev awd-tiny") {
		t.Fatal("link-local address must never be deleted")
	}
}

func TestApplyForwardsAndPruneUFW(t *testing.T) {
	var calls []string
	r := newTestReconciler(testCfg(t.TempDir()), func(_ context.Context, name string, args ...string) (string, error) {
		line := name + " " + strings.Join(args, " ")
		calls = append(calls, line)
		if name == "/usr/sbin/ufw" && len(args) == 1 && args[0] == "status" {
			return "51820/udp ALLOW Anywhere # Dyatel host=tiny\n25565/tcp ALLOW Anywhere # Dyatel host=tiny\n9999/tcp ALLOW Anywhere # Dyatel host=tiny\n9999/tcp ALLOW Anywhere # Dyatel host=other", nil
		}
		if (name == "iptables" || name == "ip6tables") && len(args) >= 3 && args[2] == "-C" {
			return "", errors.New("missing jump")
		}
		return "", nil
	})

	h := store.Host{
		Name:       "tiny",
		Transport:  "wireguard",
		ListenPort: 51820,
		TunnelIPv4: "10.66.66.2/32",
		TunnelIPv6: "fd66:66::2/128",
	}
	fwds := []store.Forward{{PublicPort: 25565, TargetPort: 25565, Proto: "tcp"}}

	r.applyForwards(context.Background(), "wgd-tiny", h, fwds)

	for _, want := range []string{
		"/usr/sbin/ufw allow 51820/udp comment Dyatel host=tiny",
		"/usr/sbin/ufw allow 25565/tcp comment Dyatel host=tiny",
		"/usr/sbin/ufw --force delete allow 9999/tcp",
		"iptables -t nat -A DYATEL-wgd-tiny -p tcp --dport 25565 -j DNAT --to-destination 10.66.66.2:25565",
		"ip6tables -t nat -A DYATEL-wgd-tiny6 -p tcp --dport 25565 -j DNAT --to-destination [fd66:66::2]:25565",
	} {
		if !slices.Contains(calls, want) {
			t.Fatalf("missing call %q in:\n%s", want, strings.Join(calls, "\n"))
		}
	}
	// Only tiny's stale 9999/tcp should be deleted (one delete call, not two).
	deletes := 0
	for _, c := range calls {
		if c == "/usr/sbin/ufw --force delete allow 9999/tcp" {
			deletes++
		}
	}
	if deletes != 1 {
		t.Fatalf("expected exactly 1 ufw delete for tiny, got %d", deletes)
	}
}

func TestPruneOrphans(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []string{"wgd-keep.conf", "wgd-stale.conf", "awd-keep.conf", "awd-stale.conf", "unrelated.conf"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("[Interface]\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	var calls []string
	deletedJumps := map[string]int{}
	r := newTestReconciler(testCfg(dir), func(_ context.Context, name string, args ...string) (string, error) {
		line := name + " " + strings.Join(args, " ")
		calls = append(calls, line)
		if name == "ip" && len(args) >= 5 && args[3] == "type" && args[4] == "wireguard" {
			return "4: wgd-keep: <POINTOPOINT>\n5: wgd-stale: <POINTOPOINT>", nil
		}
		if name == "ip" && len(args) >= 5 && args[3] == "type" && args[4] == "tun" {
			return "6: awd-keep: <POINTOPOINT>\n7: awd-stale: <POINTOPOINT>\n8: tun0: <POINTOPOINT>", nil
		}
		if name == "iptables" && len(args) == 3 && args[2] == "-S" {
			return "-N DYATEL-wgd-keep\n-N DYATEL-wgd-stale\n-N DYATEL-wgd-stale-po", nil
		}
		if name == "ip6tables" && len(args) == 3 && args[2] == "-S" {
			return "-N DYATEL-wgd-keep6\n-N DYATEL-awd-keep-po6\n-N DYATEL-wgd-stale6\n-N DYATEL-wgd-stale-po6\n-N DYATEL-awd-stale6\n-N DYATEL-awd-stale-po6", nil
		}
		if (name == "iptables" || name == "ip6tables") && len(args) >= 6 && args[2] == "-D" {
			// Simulate one existing jump on PREROUTING for base chains and on POSTROUTING for -po chains.
			hook, chain := args[3], args[5]
			isPo := strings.HasSuffix(chain, "-po") || strings.HasSuffix(chain, "-po6")
			if (isPo && hook == "POSTROUTING") || (!isPo && hook == "PREROUTING") {
				key := name + ":" + hook + ":" + chain
				if deletedJumps[key] == 0 {
					deletedJumps[key]++
					return "", nil
				}
			}
			return "", errors.New("no jump")
		}
		if name == "/usr/sbin/ufw" && len(args) == 1 && args[0] == "status" {
			return "25565/tcp ALLOW Anywhere # Dyatel host=keep\n25566/tcp ALLOW Anywhere # Dyatel host=stale", nil
		}
		return "", nil
	})

	r.pruneOrphans(
		context.Background(),
		map[string]bool{"wgd-keep": true, "awd-keep": true},
		map[string]bool{"keep": true},
	)

	for _, want := range []string{
		"ip link delete wgd-stale",
		"systemctl stop dyatel-awg-awd-stale",
		"systemctl reset-failed dyatel-awg-awd-stale",
		"ip link delete awd-stale",
		"iptables -t nat -D PREROUTING -j DYATEL-wgd-stale",
		"iptables -t nat -D POSTROUTING -j DYATEL-wgd-stale-po",
		"iptables -t nat -F DYATEL-wgd-stale",
		"iptables -t nat -X DYATEL-wgd-stale",
		"iptables -t nat -F DYATEL-wgd-stale-po",
		"iptables -t nat -X DYATEL-wgd-stale-po",
		"ip6tables -t nat -D PREROUTING -j DYATEL-wgd-stale6",
		"ip6tables -t nat -D POSTROUTING -j DYATEL-wgd-stale-po6",
		"ip6tables -t nat -D PREROUTING -j DYATEL-awd-stale6",
		"ip6tables -t nat -D POSTROUTING -j DYATEL-awd-stale-po6",
		"ip6tables -t nat -F DYATEL-wgd-stale6",
		"ip6tables -t nat -X DYATEL-wgd-stale6",
		"ip6tables -t nat -F DYATEL-wgd-stale-po6",
		"ip6tables -t nat -X DYATEL-wgd-stale-po6",
		"ip6tables -t nat -F DYATEL-awd-stale6",
		"ip6tables -t nat -X DYATEL-awd-stale6",
		"ip6tables -t nat -F DYATEL-awd-stale-po6",
		"ip6tables -t nat -X DYATEL-awd-stale-po6",
		"/usr/sbin/ufw --force delete allow 25566/tcp",
	} {
		if !slices.Contains(calls, want) {
			t.Fatalf("missing orphan cleanup call %q in:\n%s", want, strings.Join(calls, "\n"))
		}
	}
	for _, forbidden := range []string{
		"ip link delete wgd-keep",
		"ip link delete awd-keep",
		"ip link delete tun0",
		"systemctl stop dyatel-awg-awd-keep",
		"iptables -t nat -D PREROUTING -j DYATEL-wgd-keep",
		"iptables -t nat -X DYATEL-wgd-keep",
		"ip6tables -t nat -D PREROUTING -j DYATEL-wgd-keep6",
		"ip6tables -t nat -D POSTROUTING -j DYATEL-awd-keep-po6",
		"ip6tables -t nat -X DYATEL-wgd-keep6",
		"ip6tables -t nat -X DYATEL-awd-keep-po6",
		"/usr/sbin/ufw --force delete allow 25565/tcp",
	} {
		if slices.Contains(calls, forbidden) {
			t.Fatalf("unexpected cleanup of live/unrelated resource: %q", forbidden)
		}
	}
	for _, gone := range []string{"wgd-stale.conf", "awd-stale.conf"} {
		if _, err := os.Stat(filepath.Join(dir, gone)); !os.IsNotExist(err) {
			t.Fatalf("expected stale config %s to be deleted", gone)
		}
	}
	for _, kept := range []string{"wgd-keep.conf", "awd-keep.conf", "unrelated.conf"} {
		if _, err := os.Stat(filepath.Join(dir, kept)); err != nil {
			t.Fatalf("expected config %s to remain, got err=%v", kept, err)
		}
	}
}

func TestEnsureFromDiskRestoresOnlyDownDaemonInterfaces(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []string{"wgd-down.conf", "wgd-up.conf", "unrelated.conf"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("[Interface]\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	var calls []string
	r := newTestReconciler(testCfg(dir), func(_ context.Context, name string, args ...string) (string, error) {
		line := name + " " + strings.Join(args, " ")
		calls = append(calls, line)
		if name == "ip" && len(args) == 3 && args[0] == "link" && args[1] == "show" && args[2] == "wgd-up" {
			return "up", nil
		}
		if name == "ip" && len(args) == 3 && args[0] == "link" && args[1] == "show" && args[2] == "wgd-down" {
			return "", errors.New("does not exist")
		}
		return "", nil
	})

	r.ensureFromDisk(context.Background())

	joined := strings.Join(calls, "\n")
	if !strings.Contains(joined, "ip link add wgd-down type wireguard") {
		t.Fatalf("expected wgd-down bring-up, got:\n%s", joined)
	}
	if strings.Contains(joined, "wgd-up.conf") || strings.Contains(joined, "unrelated.conf") {
		t.Fatalf("unexpected bring-up for live/unrelated config:\n%s", joined)
	}
}

type fakeReconcileStore struct {
	hosts []store.Host
	fwds  map[uuid.UUID][]store.Forward
	err   error
}

func (f *fakeReconcileStore) HostsByNode(_ context.Context, _ string) ([]store.Host, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.hosts, nil
}

func (f *fakeReconcileStore) ForwardsByHost(_ context.Context, id uuid.UUID) ([]store.Forward, error) {
	return f.fwds[id], nil
}

func TestPassPrunesStaleConfigsBeforeDegradedMode(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []string{"wgd-deleted.conf", "awd-deleted.conf", "awd-susp.conf"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("[Interface]\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	cfg := testCfg(dir)
	cfg.XrayConfigPath = filepath.Join(dir, "xray.json")
	cfg.XrayServiceName = "xray@dyatel"

	db := &fakeReconcileStore{
		hosts: []store.Host{
			{
				ID:           uuid.New(),
				Name:         "livewg",
				Transport:    "wireguard",
				ListenPort:   51820,
				GWPrivateKey: "gwpriv",
				TunnelIPv4:   "10.66.66.2/32",
				TunnelIPv6:   "fd66:66::2/128",
				State:        "active",
			},
			{
				ID:           uuid.New(),
				Name:         "liveawg",
				Transport:    "amneziawg",
				ListenPort:   51900,
				GWPrivateKey: "gwpriv",
				TunnelIPv4:   "10.77.77.2/32",
				TunnelIPv6:   "fd77:77::2/128",
				State:        "active",
			},
			{
				ID:         uuid.New(),
				Name:       "susp",
				Transport:  "amneziawg",
				ListenPort: 51901,
				State:      "suspended",
			},
		},
	}

	var calls []string
	down := map[string]bool{}
	r := newTestReconciler(cfg, func(_ context.Context, name string, args ...string) (string, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		if name == "awg" && len(args) == 2 && args[0] == "show" && args[1] == "awd-susp" {
			return "interface: awd-susp", nil
		}
		if name == "ip" && len(args) >= 5 && args[0] == "link" && args[1] == "add" && args[4] == "amneziawg" {
			return "", errors.New("RTNETLINK answers: Operation not supported")
		}
		if name == "systemd-run" && len(args) >= 3 && args[1] == "--unit" {
			ifname := strings.TrimPrefix(args[2], "dyatel-awg-")
			delete(down, ifname)
		}
		if name == "ip" && len(args) == 3 && args[0] == "link" && args[1] == "show" {
			if down[args[2]] {
				return "", errors.New("not found")
			}
			return "up", nil
		}
		if name == "ip" && len(args) >= 5 && args[3] == "type" && args[4] == "tun" {
			return "9: awd-liveawg: <POINTOPOINT>\n10: awd-susp: <POINTOPOINT>", nil
		}
		if (name == "iptables" || name == "ip6tables") && len(args) >= 3 && (args[2] == "-C" || args[2] == "-D") {
			return "", errors.New("no jump")
		}
		return "", nil
	})
	r.db = db

	// Pass 1 (DB healthy): keeps active configs, tears down suspended AWG unit+iface, deletes stale configs.
	r.pass(context.Background())

	for _, kept := range []string{"wgd-livewg.conf", "awd-liveawg.conf"} {
		if _, err := os.Stat(filepath.Join(dir, kept)); err != nil {
			t.Fatalf("expected active config %s to be preserved, got %v", kept, err)
		}
	}
	for _, gone := range []string{"wgd-deleted.conf", "awd-deleted.conf", "awd-susp.conf"} {
		if _, err := os.Stat(filepath.Join(dir, gone)); !os.IsNotExist(err) {
			t.Fatalf("expected stale/suspended config %s to be deleted", gone)
		}
	}
	if !slices.Contains(calls, "systemctl stop dyatel-awg-awd-susp") {
		t.Fatalf("expected suspended AWG userspace unit to stop, calls:\n%s", strings.Join(calls, "\n"))
	}

	// Pass 2 (DB outage + reboot): degraded mode brings up active interfaces only; deleted/suspended stay dead.
	calls = nil
	down["wgd-livewg"] = true
	down["awd-liveawg"] = true
	down["wgd-deleted"] = true
	down["awd-deleted"] = true
	down["awd-susp"] = true
	db.err = errors.New("connection refused")

	r.pass(context.Background())

	joined := strings.Join(calls, "\n")
	if !strings.Contains(joined, "ip link add wgd-livewg type wireguard") {
		t.Fatalf("expected degraded mode to restore wgd-livewg, got:\n%s", joined)
	}
	if !strings.Contains(joined, "systemd-run --unit dyatel-awg-awd-liveawg") {
		t.Fatalf("expected degraded mode to restore awd-liveawg, got:\n%s", joined)
	}
	for _, dead := range []string{"wgd-deleted", "awd-deleted", "awd-susp"} {
		if strings.Contains(joined, dead) {
			t.Fatalf("degraded mode resurrected deleted/suspended host %s:\n%s", dead, joined)
		}
	}
}

type fakeDNSStore struct {
	recs []store.DNSRecord
	ids  map[uuid.UUID]string
}

func (f *fakeDNSStore) ActiveDNSRecordsByNode(_ context.Context, _ string) ([]store.DNSRecord, error) {
	return f.recs, nil
}

func (f *fakeDNSStore) SetDNSCloudflareID(_ context.Context, id uuid.UUID, cfID string) error {
	if f.ids == nil {
		f.ids = map[uuid.UUID]string{}
	}
	f.ids[id] = cfID
	return nil
}

func TestReconcileDNS(t *testing.T) {
	var created []string
	var deleted []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"result":  []map[string]string{{"id": "z1", "name": "nada.mu"}},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/zones/z1/dns_records":
			if r.URL.Query().Get("name") == "mc1.test.nada.mu" {
				_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": []any{}})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"result": []map[string]any{
					{"id": "cf-a", "type": "A", "name": "mc1.test.nada.mu", "content": "81.30.105.65", "comment": "dyatel node=test fwd=f1"},
					{"id": "cf-old", "type": "A", "name": "stale.test.nada.mu", "content": "81.30.105.65", "comment": "dyatel node=test fwd=old"},
				},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/zones/z1/dns_records":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			created = append(created, body["type"].(string)+":"+body["name"].(string)+"="+body["content"].(string))
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]any{"id": "cf-" + body["type"].(string)}})
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/zones/z1/dns_records/"):
			deleted = append(deleted, strings.TrimPrefix(r.URL.Path, "/zones/z1/dns_records/"))
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]string{}})
		}
	}))
	defer srv.Close()

	recID := uuid.New()
	fwdID := uuid.New()
	cfg := testCfg(t.TempDir())
	cfg.Node = "test"
	cfg.DNSZone = "test.nada.mu"
	cfg.PublicIPv4 = "81.30.105.65"
	cfg.PublicIPv6 = "2a13:d207:494:21::1"

	r := New(cfg, nil)
	r.dns = dns.New("tok").WithBaseURL(srv.URL)
	r.dnsDB = &fakeDNSStore{
		recs: []store.DNSRecord{{
			ID:        recID,
			ForwardID: fwdID,
			Name:      "mc1.test.nada.mu",
		}},
	}

	r.reconcileDNS(context.Background())

	if len(created) != 2 {
		t.Fatalf("expected A and AAAA creation, got %v", created)
	}
	if !slices.Contains(deleted, "cf-old") {
		t.Fatalf("expected stale record cf-old deletion, got %v", deleted)
	}
	if got := r.dnsDB.(*fakeDNSStore).ids[recID]; got != "cf-A,cf-AAAA" {
		t.Fatalf("saved cloudflare_id = %q, want cf-A,cf-AAAA", got)
	}
}

func TestReconcileDNSRequiresExplicitPublicIP(t *testing.T) {
	cfg := testCfg(t.TempDir())
	cfg.Node = "test"
	cfg.DNSZone = "test.nada.mu"
	cfg.CloudflareToken = "tok"
	cfg.PublicIPv4 = ""
	cfg.PublicIPv6 = ""

	r := New(cfg, nil)
	r.dnsDB = &fakeDNSStore{recs: []store.DNSRecord{{
		ID:        uuid.New(),
		ForwardID: uuid.New(),
		Name:      "mc1.test.nada.mu",
	}}}

	r.reconcileDNS(context.Background())
	st := r.dnsStatus()
	if st.LastSync == nil {
		t.Fatal("expected a sync attempt to be recorded")
	}
	if !strings.Contains(st.LastError, "not configured") {
		t.Fatalf("last_error = %q, want a missing-public-IP error", st.LastError)
	}
}
