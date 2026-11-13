package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// gen runs a gen subcommand with flags and returns stdout — the whole
// command is offline, so tests need no daemon, no DB, no env fixtures.
func gen(t *testing.T, args ...string) string {
	t.Helper()
	resetGenFlags(t)
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	// Execute on a child redirects to the root, so drive the root with
	// explicit args and let cobra resolve the gen subcommand tree.
	rootCmd.SetArgs(append([]string{"gen"}, args...))
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("gen %v: %v", args, err)
	}
	return buf.String()
}

// resetGenFlags restores flag defaults: cobra flag values are global
// package state and survive across Execute calls, so one test's --name
// would leak into the next and mask missing-flag errors.
func resetGenFlags(t *testing.T) {
	t.Helper()
	for _, sub := range []*cobra.Command{genWGCmd, genXrayCmd} {
		sub.Flags().VisitAll(func(f *pflag.Flag) {
			_ = f.Value.Set(f.DefValue)
		})
	}
}

func TestGenWireguard(t *testing.T) {
	out := gen(t, "wireguard", "--name", "demo", "--port", "51821",
		"--proxer-pubkey", "PROXERPUB", "--client-pubkey", "CLIENTPUB")
	for _, want := range []string{
		"=== berg (gw) config ===",
		"ListenPort = 51821",
		"PublicKey = PROXERPUB",
		"PublicKey = CLIENTPUB",
		"=== proxer config ===",
		"=== client config ===",
		"Endpoint = dyatel.test.nada.mu:51821",
		"# psk (generated): ",
		"# berg gw private key (generated): ",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("wireguard gen output missing %q\noutput:\n%s", want, out)
		}
	}
}

func TestGenWireguardDefaultsSkipCoreListenIP(t *testing.T) {
	out := gen(t, "wireguard", "--name", "demo", "--proxer-pubkey", "PROXERPUB")
	// berg holds CoreListenIP; proxer must get the next one, not collide.
	if !strings.Contains(out, "Address = 10.13.36.2/32") {
		t.Errorf("proxer should default to 10.13.36.2 (berg holds .1):\n%s", out)
	}
	if strings.Count(out, "AllowedIPs = 10.13.36.2,") != 1 {
		t.Errorf("proxer tunnel IP should appear exactly once in berg config:\n%s", out)
	}
}

func TestGenClientConfigSkippedWithoutConsumerKey(t *testing.T) {
	out := gen(t, "wireguard", "--name", "demo")
	if !strings.Contains(out, "register a consumer BYOK key") {
		t.Errorf("client config should be skipped with a hint:\n%s", out)
	}
	if strings.Contains(out, "=== client config ===") {
		t.Errorf("client config rendered without a consumer key:\n%s", out)
	}
}

func TestGenAmneziaAWG(t *testing.T) {
	out := gen(t, "wireguard", "--name", "demo", "--transport", "amneziawg", "--proxer-pubkey", "P")
	for _, want := range []string{"ListenPort = 51900", "Jc = "} {
		if !strings.Contains(out, want) {
			t.Errorf("amneziawg gen missing %q:\n%s", want, out)
		}
	}
}

func TestGenXray(t *testing.T) {
	out := gen(t, "xray", "--name", "demo", "--forwards", "5201:22", "--sni", "s.example")
	for _, want := range []string{
		"\"protocol\": \"vless\"",
		"\"serverName\": \"s.example\"",
		"\"dokodemo-door\"",
		"\"port\": 22",
		"\"outboundTag\": \"vless\"",
		"# vless uuid (generated): ",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("xray gen missing %q:\n%s", want, out)
		}
	}
}

func TestGenErrors(t *testing.T) {
	cases := [][]string{
		{"wireguard"},
		{"wireguard", "--name", "d", "--transport", "bogus"},
		{"xray", "--name", "d", "--forwards", "onlyone"},
	}
	for _, args := range cases {
		resetGenFlags(t)
		var buf bytes.Buffer
		rootCmd.SetOut(&buf)
		rootCmd.SetErr(&buf)
		rootCmd.SetArgs(append([]string{"gen"}, args...))
		if err := rootCmd.Execute(); err == nil {
			t.Errorf("gen %v should fail", args)
		}
	}
}
