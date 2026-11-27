package reconcile

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"nadamu/dyatel/internal/config"
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
		"pk1\tpsk\t1.2.3.4:5555\t10.66.66.2/32\t1700000000\t120\t340\t25\n" +
		"pk2\tpsk\t(none)\t10.66.66.3/32\t0\t0\t0\toff\n"
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
	var calls []string
	r := newTestReconciler(testCfg(t.TempDir()), func(_ context.Context, name string, args ...string) (string, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		if name == "ip" && len(args) >= 5 && args[3] == "type" && args[4] == "wireguard" {
			return "4: wgd-keep: <POINTOPOINT>\n5: wgd-stale: <POINTOPOINT>", nil
		}
		if name == "iptables" && len(args) == 3 && args[2] == "-S" {
			return "-N DYATEL-wgd-keep\n-N DYATEL-wgd-stale\n-N DYATEL-wgd-stale-po", nil
		}
		if name == "iptables" && len(args) >= 3 && args[2] == "-D" {
			return "", errors.New("no jump")
		}
		if name == "/usr/sbin/ufw" && len(args) == 1 && args[0] == "status" {
			return "25565/tcp ALLOW Anywhere # Dyatel host=keep\n25566/tcp ALLOW Anywhere # Dyatel host=stale", nil
		}
		return "", nil
	})

	r.pruneOrphans(context.Background(), map[string]bool{"wgd-keep": true}, map[string]bool{"keep": true})

	for _, want := range []string{
		"ip link delete wgd-stale",
		"iptables -t nat -X DYATEL-wgd-stale",
		"iptables -t nat -X DYATEL-wgd-stale-po",
		"/usr/sbin/ufw --force delete allow 25566/tcp",
	} {
		if !slices.Contains(calls, want) {
			t.Fatalf("missing orphan cleanup call %q in %v", want, calls)
		}
	}
	for _, forbidden := range []string{
		"ip link delete wgd-keep",
		"iptables -t nat -X DYATEL-wgd-keep",
		"/usr/sbin/ufw --force delete allow 25565/tcp",
	} {
		if slices.Contains(calls, forbidden) {
			t.Fatalf("unexpected cleanup of live resource: %q", forbidden)
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
