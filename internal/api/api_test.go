package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	"nadamu/dyatel/internal/config"
	"nadamu/dyatel/internal/reconcile"
	"nadamu/dyatel/internal/store"
)

// testServer opens a Store against DYATEL_TEST_DSN, applies migrations, and
// wires a full API Server. Tests are skipped without the env var so `go test`
// stays green on machines without a reachable PG (CI laptops, containers).
func testServer(t *testing.T) *Server {
	t.Helper()
	dsn := os.Getenv("DYATEL_TEST_DSN")
	if dsn == "" {
		t.Skip("DYATEL_TEST_DSN not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
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
		HostIPMin:           2,
		HostIPMax:           250,
		AWGMTU:              1280,
		TunnelIPv6NetWG:     "fd66:66::/64",
		TunnelIPv6NetAWG:    "fd77:77::/64",
		PortPoolWGMin:       51820,
		PortPoolWGMax:       51889,
		PortPoolAWGMin:      51900,
		PortPoolAWGMax:      51999,
		PortPoolXrayMin:     5200,
		PortPoolXrayMax:     5299,
		AuthentikAdminGroup: "Dyatel Admins",
		FallbackAdminUser:   "breakglass",
		// Real argon2id PHC for password "correcthorse" (m=64MiB is slow but
		// fine for a handful of requests in tests).
		FallbackAdminHash: "$argon2id$v=19$m=65536,t=2,p=1$0Zh50ymKo7qzu6LzLbJbyw$++EE7ecjdmShgjkPBEIKolDFe0PuLkQ5OqyZrqUmhL0",
	}
	return New(cfg, st, reconcile.New(cfg, st))
}

func do(t *testing.T, s *Server, method, path, sub, basic string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rdr)
	if sub != "" {
		req.Header.Set("X-Dyatel-Sub", sub)
	}
	if basic != "" {
		req.SetBasicAuth("breakglass", basic)
	}
	rec := httptest.NewRecorder()
	s.Router().ServeHTTP(rec, req)
	return rec
}

// TestFallbackAdminBasicAuth covers the break-glass path: correct Basic creds
// yield an admin identity; wrong ones must not leak a session.
func TestFallbackAdminBasicAuth(t *testing.T) {
	s := testServer(t)
	rec := do(t, s, "GET", "/api/v1/me", "", "correcthorse", nil)
	if rec.Code != 200 {
		t.Fatalf("me via fallback admin: got %d: %s", rec.Code, rec.Body)
	}
	var me struct {
		IsAdmin bool   `json:"is_admin"`
		Auth    string `json:"auth"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &me); err != nil {
		t.Fatal(err)
	}
	if !me.IsAdmin || me.Auth != "fallback" {
		t.Fatalf("fallback admin identity: %+v", me)
	}
	rec = do(t, s, "GET", "/api/v1/me", "", "wrongpass", nil)
	if rec.Code != 401 {
		t.Fatalf("bad fallback password: got %d, want 401", rec.Code)
	}
}

func TestTrustedSubDoesNotOverwriteDisplayName(t *testing.T) {
	s := testServer(t)
	sub := fmt.Sprintf("trusted-sub-%d", time.Now().UnixNano())

	// 1. Lazy creation via trusted-sub sets sub as initial fallback display_name.
	rec := do(t, s, "GET", "/api/v1/me", sub, "", nil)
	if rec.Code != 200 {
		t.Fatalf("lazy provision via /me: got %d: %s", rec.Code, rec.Body)
	}
	var me struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &me); err != nil {
		t.Fatal(err)
	}
	if me.Name != sub {
		t.Fatalf("initial display name: got %q, want %q", me.Name, sub)
	}

	// 2. Real OIDC name overwrites the bare sub fallback.
	if got, err := s.st.CreateUser(context.Background(), sub, "Danya"); err != nil {
		t.Fatalf("update with real name: %v", err)
	} else if got.DisplayName != "Danya" {
		t.Fatalf("real name did not replace sub fallback: got %q, want %q", got.DisplayName, "Danya")
	}

	// 3. Subsequent trusted-sub auth keeps the real display_name.
	rec = do(t, s, "GET", "/api/v1/me", sub, "", nil)
	if rec.Code != 200 {
		t.Fatalf("re-sync via /me: got %d: %s", rec.Code, rec.Body)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &me); err != nil {
		t.Fatal(err)
	}
	if me.Name != "Danya" {
		t.Fatalf("bare sub overwrote display name: got %q, want %q", me.Name, "Danya")
	}
}

// TestStatusAdminOnly: status is admin-gated (403 for non-admins).
func TestStatusAdminOnly(t *testing.T) {
	s := testServer(t)
	if rec := do(t, s, "GET", "/api/v1/status", "alice@example.test", "", nil); rec.Code != 403 {
		t.Fatalf("status as non-admin: got %d, want 403", rec.Code)
	}
	if rec := do(t, s, "GET", "/api/v1/status", "", "correcthorse", nil); rec.Code != 200 {
		t.Fatalf("status as fallback admin: got %d", rec.Code)
	}
}

// TestListHostsEmptyIsArray pins the client contract: empty host lists must
// encode as [] (not null), so dyatelctl and the panel can range over them.
func TestListHostsEmptyIsArray(t *testing.T) {
	s := testServer(t)
	rec := do(t, s, "GET", "/api/v1/hosts", "nobody@example.test", "", nil)
	if rec.Code != 200 {
		t.Fatalf("listHosts: got %d: %s", rec.Code, rec.Body)
	}
	if got := rec.Body.String(); got != "[]\n" {
		t.Fatalf("empty hosts must encode as [], got %q", got)
	}
	// Admin sees every host in the DB (shared test DB, leftovers included),
	// so only pin the array-not-null contract for the admin view.
	rec = do(t, s, "GET", "/api/v1/hosts", "", "correcthorse", nil)
	if rec.Code != 200 || !bytes.HasPrefix(bytes.TrimSpace(rec.Body.Bytes()), []byte("[")) {
		t.Fatalf("admin hosts: got %d %q", rec.Code, rec.Body.String())
	}
}

// TestUnauthenticatedIs401: no creds at all -> 401, not 403 or 500.
func TestUnauthenticatedIs401(t *testing.T) {
	s := testServer(t)
	if rec := do(t, s, "GET", "/api/v1/hosts", "", "", nil); rec.Code != 401 {
		t.Fatalf("no creds: got %d, want 401", rec.Code)
	}
}

// TestHostLifecycle exercises the owner flow: create (BYOK proxer key,
// consumer invitation), fetch, list visibility for owner vs stranger, and
// delete. The consumer is a third identity, created lazily via /me.
func TestHostLifecycle(t *testing.T) {
	s := testServer(t)
	owner := "owner@example.test"
	consumerSub := "consumer@example.test"
	stranger := "stranger@example.test"

	// Create the consumer user lazily via the trusted-header path.
	rec := do(t, s, "GET", "/api/v1/me", consumerSub, "", nil)
	if rec.Code != 200 {
		t.Fatalf("create consumer via /me: got %d: %s", rec.Code, rec.Body)
	}
	var consumer struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &consumer); err != nil {
		t.Fatal(err)
	}

	in := map[string]any{
		// Unique name: the test DB is shared across runs, and hosts_name_key
		// is unique. validName allows a-z0-9-, 32 chars max.
		"name":          "lifecycle-" + strconv.FormatInt(time.Now().UnixNano(), 36),
		"wg_public_key": "aGVsbG8gd29ybGQgMTIzNDU2Nzg5MEFCQ0RFRg==",
		"transport":     "wireguard",
		"consumer_id":   consumer.ID,
	}
	rec = do(t, s, "POST", "/api/v1/hosts", owner, "", in)
	if rec.Code != 200 && rec.Code != 201 {
		t.Fatalf("createHost: got %d: %s", rec.Code, rec.Body)
	}
	var h store.Host
	if err := json.Unmarshal(rec.Body.Bytes(), &h); err != nil {
		t.Fatal(err)
	}
	if h.GWPrivateKey != "" || h.WGPreSharedKey != "" {
		t.Fatal("create response must not leak gw private key or PSK")
	}
	// Owner sees it in their list.
	rec = do(t, s, "GET", "/api/v1/hosts", owner, "", nil)
	var list []store.Host
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("list decode: %v (%s)", err, rec.Body)
	}
	found := false
	for _, x := range list {
		if x.ID == h.ID {
			found = true
		}
	}
	if !found {
		t.Fatal("owner cannot see own host in list")
	}
	// Stranger cannot see it.
	rec = do(t, s, "GET", "/api/v1/hosts", stranger, "", nil)
	var strangerList []store.Host
	_ = json.Unmarshal(rec.Body.Bytes(), &strangerList)
	for _, x := range strangerList {
		if x.ID == h.ID {
			t.Fatal("stranger sees foreign host")
		}
	}
	// Stranger cannot fetch/delete it.
	path := fmt.Sprintf("/api/v1/hosts/%s", h.ID)
	if rec := do(t, s, "GET", path, stranger, "", nil); rec.Code != 403 && rec.Code != 404 {
		t.Fatalf("stranger get host: got %d", rec.Code)
	}
	if rec := do(t, s, "DELETE", path, "stranger@example.test", "", nil); rec.Code != 403 && rec.Code != 404 {
		t.Fatalf("stranger delete host: got %d", rec.Code)
	}
	// Forwards list: empty must be [] as well.
	rec = do(t, s, "GET", path+"/forwards", owner, "", nil)
	if rec.Code != 200 || rec.Body.String() == "null\n" {
		t.Fatalf("empty forwards: got %d %q", rec.Code, rec.Body.String())
	}
	// Owner delete returns 204.
	if rec := do(t, s, "DELETE", path, owner, "", nil); rec.Code != 204 {
		t.Fatalf("owner delete: got %d: %s", rec.Code, rec.Body)
	}
	if rec := do(t, s, "GET", path, owner, "", nil); rec.Code != 404 {
		t.Fatalf("deleted host get: got %d, want 404", rec.Code)
	}
}

func TestNormalizeDNSName(t *testing.T) {
	if got, err := normalizeDNSName("mc1", "test.nada.mu"); err != nil || got != "mc1.test.nada.mu" {
		t.Fatalf("short label: got (%q, %v)", got, err)
	}
	if got, err := normalizeDNSName("MC1.Test.Nada.Mu.", "test.nada.mu"); err != nil || got != "mc1.test.nada.mu" {
		t.Fatalf("fqdn normalization: got (%q, %v)", got, err)
	}
	for _, bad := range []string{"", "test.nada.mu", "-bad", "bad-", "bad_char", "a..b"} {
		if _, err := normalizeDNSName(bad, "test.nada.mu"); err == nil {
			t.Fatalf("expected error for %q", bad)
		}
	}
}

func TestForwardDNSLifecycle(t *testing.T) {
	s := testServer(t)
	s.cfg.DNSZone = "test.nada.mu"
	owner := "dns-owner@example.test"
	consRec := do(t, s, "GET", "/api/v1/me", "dns-cons@example.test", "", nil)
	if consRec.Code != 200 {
		t.Fatalf("provision consumer: %d", consRec.Code)
	}
	var cons struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(consRec.Body.Bytes(), &cons)

	hName := "dns-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	hRec := do(t, s, "POST", "/api/v1/hosts", owner, "", map[string]any{
		"name":          hName,
		"wg_public_key": "aGVsbG8gd29ybGQgMTIzNDU2Nzg5MEFCQ0RFRg==",
		"transport":     "wireguard",
		"consumer_id":   cons.ID,
	})
	if hRec.Code != 200 && hRec.Code != 201 {
		t.Fatalf("create host: %d %s", hRec.Code, hRec.Body)
	}
	var h store.Host
	_ = json.Unmarshal(hRec.Body.Bytes(), &h)
	t.Cleanup(func() {
		_ = do(t, s, "DELETE", "/api/v1/hosts/"+h.ID.String(), owner, "", nil)
	})

	fRec := do(t, s, "POST", "/api/v1/hosts/"+h.ID.String()+"/forwards", owner, "", map[string]any{
		"public_port": 25577, "target_port": 25577, "proto": "tcp", "label": "mc",
	})
	if fRec.Code != 200 {
		t.Fatalf("create forward: %d %s", fRec.Code, fRec.Body)
	}
	var fwd store.Forward
	_ = json.Unmarshal(fRec.Body.Bytes(), &fwd)

	sub := "play-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	// Stranger / consumer cannot bind DNS on someone else's forward.
	if rec := do(t, s, "POST", "/api/v1/forwards/"+fwd.ID.String()+"/dns", "dns-cons@example.test", "", map[string]string{"name": sub}); rec.Code != 403 {
		t.Fatalf("consumer set dns: got %d, want 403", rec.Code)
	}

	dRec := do(t, s, "POST", "/api/v1/forwards/"+fwd.ID.String()+"/dns", owner, "", map[string]string{"name": sub})
	if dRec.Code != 200 {
		t.Fatalf("set dns: %d %s", dRec.Code, dRec.Body)
	}
	var dr store.DNSRecord
	_ = json.Unmarshal(dRec.Body.Bytes(), &dr)
	if dr.Name != sub+".test.nada.mu" {
		t.Fatalf("dns name = %q, want %s.test.nada.mu", dr.Name, sub)
	}

	// A second forward cannot claim a name that is already bound: the unique
	// constraint must surface as 409, not as a raw Postgres error.
	f2Rec := do(t, s, "POST", "/api/v1/hosts/"+h.ID.String()+"/forwards", owner, "", map[string]any{
		"public_port": 25578, "target_port": 25578, "proto": "tcp", "label": "mc2",
	})
	if f2Rec.Code != 200 {
		t.Fatalf("create second forward: %d %s", f2Rec.Code, f2Rec.Body)
	}
	var fwd2 store.Forward
	_ = json.Unmarshal(f2Rec.Body.Bytes(), &fwd2)
	if rec := do(t, s, "POST", "/api/v1/forwards/"+fwd2.ID.String()+"/dns", owner, "", map[string]string{"name": sub}); rec.Code != 409 {
		t.Fatalf("duplicate dns name: got %d %s, want 409", rec.Code, rec.Body)
	}

	listRec := do(t, s, "GET", "/api/v1/hosts/"+h.ID.String()+"/dns", "dns-cons@example.test", "", nil)
	if listRec.Code != 200 {
		t.Fatalf("list host dns: %d %s", listRec.Code, listRec.Body)
	}
	var list []store.DNSRecord
	_ = json.Unmarshal(listRec.Body.Bytes(), &list)
	if len(list) != 1 || list[0].Name != dr.Name {
		t.Fatalf("unexpected host dns list: %+v", list)
	}

	if delRec := do(t, s, "DELETE", "/api/v1/forwards/"+fwd.ID.String()+"/dns", owner, "", nil); delRec.Code != 204 {
		t.Fatalf("delete dns: got %d %s", delRec.Code, delRec.Body)
	}
}
