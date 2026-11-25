package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"nadamu/dyatel/internal/api"
	"nadamu/dyatel/internal/config"
	"nadamu/dyatel/internal/reconcile"
	"nadamu/dyatel/internal/store"
)

// TestAgainstRealDaemon exercises the full CLI-facing lifecycle against a
// real api.Router (store-backed, no mocks): identity, host creation with a
// separate consumer, BYOK key registration, client config, forward
// round-trip, state flips and deletion. It imports daemon internals —
// that is allowed in _test.go only and keeps the shipped CLI decoupled.
func TestAgainstRealDaemon(t *testing.T) {
	dsn := os.Getenv("DYATEL_TEST_DSN")
	if dsn == "" {
		t.Skip("DYATEL_TEST_DSN not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(st.Pool.Close)
	if err := st.MigrateUp(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	cfg := &config.Config{
		Bind:                "127.0.0.1:0",
		DatabaseDSN:         dsn,
		ReconcileEverySec:   15,
		Node:                "test",
		TunnelIPv4NetWG:     "10.66.66.0/24",
		TunnelIPv4NetAWG:    "10.77.77.0/24",
		TunnelIPv6NetWG:     "fd66:66::/64",
		TunnelIPv6NetAWG:    "fd77:77::/64",
		HostIPMin:           16,
		HostIPMax:           250,
		AWGMTU:              1280,
		PortPoolWGMin:       51820,
		PortPoolWGMax:       51889,
		PortPoolAWGMin:      51900,
		PortPoolAWGMax:      51999,
		PortPoolXrayMin:     5200,
		PortPoolXrayMax:     5299,
		AuthentikAdminGroup: "Dyatel Admins",
		FallbackAdminUser:   "breakglass",
		// Real argon2id PHC for password "correcthorse" (same hash as the
		// api package tests).
		FallbackAdminHash: "$argon2id$v=19$m=65536,t=2,p=1$0Zh50ymKo7qzu6LzLbJbyw$++EE7ecjdmShgjkPBEIKolDFe0PuLkQ5OqyZrqUmhL0",
	}
	srv := httptest.NewServer(api.New(cfg, st, reconcile.New(cfg, st)).Router())
	t.Cleanup(srv.Close)

	// The break-glass admin drives the whole lifecycle via the client.
	admin := New(srv.URL, "", "breakglass", "correcthorse")

	me, err := admin.Me()
	if err != nil {
		t.Fatalf("me: %v", err)
	}
	// The break-glass admin is provisioned with a sentinel sub (never a
	// real Authentik sub), so the identity must carry it as-is.
	if !me.IsAdmin || me.Auth != "fallback" || me.Sub != "fallback-admin" {
		t.Fatalf("admin identity: %+v", me)
	}
	if _, err := admin.Status(); err != nil {
		t.Fatalf("status: %v", err)
	}

	// Provision a plain consumer through the trusted-header path (the CLI
	// never sends this header; it exists for the daemon's local callers).
	consumerID := provisionUser(t, srv.URL, "cli-it-consumer@example.test")

	// Unique per run: the DB is shared between test packages and reruns.
	name := "cli-it-" + strconv.FormatInt(time.Now().UnixNano(), 36)

	// Create via the raw path so the response body can be inspected for
	// daemon-generated secrets (the api package pins this contract; here
	// we verify the client's view of it).
	raw, err := admin.Do(http.MethodPost, "/hosts/", CreateHostRequest{
		Name:       name,
		Transport:  "wireguard",
		ConsumerID: consumerID,
		Keepalive:  25,
	})
	if err != nil {
		t.Fatalf("create host: %v", err)
	}
	var blob map[string]any
	if err := json.Unmarshal(raw, &blob); err != nil {
		t.Fatalf("create response: %s (%v)", raw, err)
	}
	// The daemon serializes the untagged store struct, so these keys are
	// present but must be empty values.
	for _, secret := range []string{"GWPrivateKey", "WGPreSharedKey"} {
		if v, _ := blob[secret].(string); v != "" {
			t.Fatalf("create response leaked %s", secret)
		}
	}
	var h Host
	if err := json.Unmarshal(raw, &h); err != nil {
		t.Fatal(err)
	}
	if h.ID == "" || h.ConsumerID != consumerID || h.ListenPort == 0 || h.State == "" {
		t.Fatalf("created host incomplete: %+v", h)
	}

	got, err := admin.GetHost(h.ID)
	if err != nil {
		t.Fatalf("get host: %v", err)
	}
	// The berg gw keypair is generated at create; the consumer's own key
	// (WGPublicKey) stays empty until BYOK registration below.
	if got.ID != h.ID || got.GWPublicKey == "" {
		t.Fatalf("fetched host: %+v", got)
	}

	if err := admin.RegisterConsumerKey(h.ID, strings.Repeat("B", 44)); err != nil {
		t.Fatalf("register consumer key: %v", err)
	}
	cfgText, err := admin.ClientConfig(h.ID)
	if err != nil {
		t.Fatalf("client config after key registration: %v", err)
	}
	if !strings.HasPrefix(string(cfgText), "[Interface]") {
		t.Fatalf("client config text: %q", cfgText)
	}
	if _, err := admin.ProxerConfig(h.ID); err != nil {
		t.Fatalf("proxer config: %v", err)
	}

	f, err := admin.CreateForward(h.ID, CreateForwardRequest{
		PublicPort: 25565, TargetPort: 25565, Proto: "tcp", Label: "it",
	})
	if err != nil {
		t.Fatalf("create forward: %v", err)
	}
	fs, err := admin.ListForwards(h.ID)
	if err != nil || len(fs) != 1 || fs[0].ID != f.ID {
		t.Fatalf("list forwards: %v %+v", err, fs)
	}
	if err := admin.DeleteForward(h.ID, f.ID); err != nil {
		t.Fatalf("delete forward: %v", err)
	}
	if fs, err := admin.ListForwards(h.ID); err != nil || len(fs) != 0 {
		t.Fatalf("forwards after delete (want []): %v %+v", err, fs)
	}

	if err := admin.SetState(h.ID, "suspended"); err != nil {
		t.Fatalf("suspend: %v", err)
	}
	if got, err := admin.GetHost(h.ID); err != nil || got.State != "suspended" {
		t.Fatalf("state after suspend: %+v %v", got, err)
	}

	if err := admin.DeleteHost(h.ID); err != nil {
		t.Fatalf("delete host: %v", err)
	}
	_, err = admin.GetHost(h.ID)
	apiErr, ok := err.(*APIError)
	if !ok || apiErr.Status != 404 {
		t.Fatalf("get after delete: want 404 APIError, got %v", err)
	}
}

// provisionUser creates a user via the trusted header and returns its UUID.
func provisionUser(t *testing.T, base, sub string) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, base+"/api/v1/me", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Dyatel-Sub", sub)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("provision %s: got %d: %s", sub, resp.StatusCode, raw)
	}
	var me Me
	if err := json.Unmarshal(raw, &me); err != nil {
		t.Fatalf("provision me: %v", err)
	}
	return me.ID
}
