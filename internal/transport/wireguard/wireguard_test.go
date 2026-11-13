package wireguard

import (
	"strings"
	"testing"

	"nadamu/dyatel/internal/config"
	"nadamu/dyatel/internal/store"
)

func testWG() *WG {
	return New(&config.Config{
		TunnelIPv4Net:      "10.13.36.0/24",
		TunnelIPv6Net:      "fd00:36::/64",
		PublicEndpointHost: "dyatel.test.nada.mu",
		CoreListenIP:       "10.13.36.1",
	})
}

func testHost(name, transport string) store.Host {
	return store.Host{
		Name:          name,
		Transport:     transport,
		State:         "active",
		ListenPort:    51820,
		WGPublicKey:   "pUbKey1234567890pUbKey1234567890pU=",
		GWPrivateKey:  "GAMyPr1vateKeyNeverSeen",
		GWPublicKey:   "gWpub",
		WGPreSharedKey: "pSk1234567890pSk1234567890pSk1234=",
		TunnelIPv4:    "10.13.36.2/32",
		TunnelIPv6:    "fd00:36::2/128",
		Keepalive:     25,
	}
}

func TestInterfaceName(t *testing.T) {
	_ = testWG()
	h := testHost("myhost", "wireguard")
	if got := InterfaceName(h); got != "wgd-myhost" {
		t.Fatalf("ifname = %q", got)
	}
	long := testHost("a-very-long-host-name-exceeding-limit", "wireguard")
	if got := len(InterfaceName(long)); got > 15 {
		t.Fatalf("ifname too long: %q", InterfaceName(long))
	}
}

func TestRenderProxerConfig(t *testing.T) {
	w := testWG()
	cfgB, err := w.RenderProxerConfig(testHost("myhost", "wireguard"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := string(cfgB)
	for _, want := range []string{
		"Address = 10.13.36.2/32, fd00:36::2/128",
		"PrivateKey = " + PrivateKeyPlaceholder,
		"Endpoint = dyatel.test.nada.mu:51820",
		"AllowedIPs = 10.13.36.1/32, fd00:36::1/128",
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("missing %q in:\n%s", want, cfg)
		}
	}
	if strings.Contains(cfg, "GAMyPr1vateKeyNeverSeen") {
		t.Error("gw private key leaked into proxer config")
	}
}

func TestRenderClientConfigGatesOnConsumer(t *testing.T) {
	w := testWG()
	h := testHost("myhost", "wireguard")
	if _, err := w.RenderClientConfig(h); err == nil {
		t.Fatal("expected error without consumer key")
	}
	pub := "cPubKey1234567890cPubKey1234567890cU="
	h.ConsumerWGPublicKey = &pub
	v4, v6 := "10.13.36.3/32", "fd00:36::3/128"
	h.ConsumerTunnelIPv4, h.ConsumerTunnelIPv6 = &v4, &v6
	cfgB, err := w.RenderClientConfig(h)
	if err != nil {
		t.Fatal(err)
	}
	s := string(cfgB)
	for _, want := range []string{
		"Address = 10.13.36.3/32, fd00:36::3/128",
		"AllowedIPs = 10.13.36.2/32, fd00:36::2/128",
		PrivateKeyPlaceholder,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in:\n%s", want, s)
		}
	}
}

func TestRenderGWConfigSuspendedNil(t *testing.T) {
	w := testWG()
	h := testHost("myhost", "wireguard")
	h.State = "suspended"
	if cfg, _ := w.RenderGWConfig(h); cfg != nil {
		t.Fatal("suspended host must render nil")
	}
}

func TestRenderGWConfigPeers(t *testing.T) {
	w := testWG()
	h := testHost("myhost", "wireguard")
	cfgB, err := w.RenderGWConfig(h)
	if err != nil {
		t.Fatal(err)
	}
	cfg := string(cfgB)
	for _, want := range []string{
		"Address = 10.13.36.1/32, fd00:36::1/128",
		"ListenPort = 51820", "Table = off",
		"AllowedIPs = 10.13.36.2, fd00:36::2",
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("missing %q in:\n%s", want, cfg)
		}
	}
}