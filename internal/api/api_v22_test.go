package api

import (
	"bytes"
	"encoding/json"

	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

// tokenReq replays a request with a PAT bearer instead of the trusted-sub
// header, so the CLI-facing auth path is exercised end to end.
func tokenReq(t *testing.T, s *Server, method, path, token string, body any) *httptest.ResponseRecorder {
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
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	s.Router().ServeHTTP(rec, req)
	return rec
}

// TestTokenLifecycle covers RFC §3.2: mint (secret shown once), authenticate
// with it, list metadata, and revoke. A revoked token must stop working
// immediately — revoke-not-rotate is the whole point.
func TestTokenLifecycle(t *testing.T) {
	s := testServer(t)
	sub := "pat-owner@example.test"

	rec := do(t, s, "POST", "/api/v1/tokens", sub, "", map[string]string{"label": "laptop"})
	if rec.Code != 200 {
		t.Fatalf("create token: got %d: %s", rec.Code, rec.Body)
	}
	var created struct {
		ID    string `json:"id"`
		Label string `json:"label"`
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if len(created.Token) < 40 || created.Token[:7] != "dyatel_" {
		t.Fatalf("minted token has wrong shape: %q", created.Token)
	}
	// The new token must authenticate as its owner.
	rec = tokenReq(t, s, "GET", "/api/v1/me", created.Token, nil)
	if rec.Code != 200 {
		t.Fatalf("me via PAT: got %d: %s", rec.Code, rec.Body)
	}
	var me struct {
		Name string `json:"name"`
		Auth string `json:"auth"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &me)
	if me.Auth != "pat" {
		t.Fatalf("auth method via PAT: %q", me.Auth)
	}
	// Metadata list never carries the secret.
	rec = tokenReq(t, s, "GET", "/api/v1/tokens", created.Token, nil)
	if rec.Code != 200 {
		t.Fatalf("list tokens: got %d: %s", rec.Code, rec.Body)
	}
	if bytes.Contains(rec.Body.Bytes(), []byte(created.Token)) {
		t.Fatal("token list leaked the plaintext secret")
	}
	// Revoke, then the same secret must be rejected.
	rec = tokenReq(t, s, "DELETE", "/api/v1/tokens/"+created.ID, created.Token, nil)
	if rec.Code != 204 {
		t.Fatalf("revoke token: got %d: %s", rec.Code, rec.Body)
	}
	if rec := tokenReq(t, s, "GET", "/api/v1/me", created.Token, nil); rec.Code != 401 {
		t.Fatalf("revoked token still authenticates: got %d", rec.Code)
	}
	// A revoked secret no longer authenticates at all, so replaying the
	// revoke with it is a 401 (auth runs before the handler), never a 500.
	if rec := tokenReq(t, s, "DELETE", "/api/v1/tokens/"+created.ID, created.Token, nil); rec.Code != 401 {
		t.Fatalf("second revoke: got %d, want 401", rec.Code)
	}
}

// TestTokenIsolation covers two invariants the branch fixed: usage is
// recorded for the presented token only, and one user cannot revoke another
// user's token.
func TestTokenIsolation(t *testing.T) {
	s := testServer(t)
	// Unique identity per run: the shared test DB keeps rows from earlier
	// runs, and a stale "second" token would poison the last_used_at check.
	owner := "pat-iso-" + strconv.FormatInt(time.Now().UnixNano(), 36) + "@example.test"

	mint := func(label string) (id, secret string) {
		rec := do(t, s, "POST", "/api/v1/tokens", owner, "", map[string]string{"label": label})
		if rec.Code != 200 {
			t.Fatalf("mint %s: %d: %s", label, rec.Code, rec.Body)
		}
		var t1 struct {
			ID    string `json:"id"`
			Token string `json:"token"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &t1)
		return t1.ID, t1.Token
	}
	firstID, firstSecret := mint("first")
	_, secondSecret := mint("second")

	// Authenticate with the first token; the second must stay untouched.
	if rec := tokenReq(t, s, "GET", "/api/v1/me", firstSecret, nil); rec.Code != 200 {
		t.Fatalf("auth with first: %d", rec.Code)
	}
	rec := tokenReq(t, s, "GET", "/api/v1/tokens", firstSecret, nil)
	if rec.Code != 200 {
		t.Fatalf("list tokens: %d", rec.Code)
	}
	var ts []struct {
		Label      string `json:"label"`
		LastUsedAt string `json:"last_used_at"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &ts); err != nil {
		t.Fatal(err)
	}
	for _, tk := range ts {
		switch tk.Label {
		case "first":
			if tk.LastUsedAt == "" {
				t.Fatal("presented token has no last_used_at")
			}
		case "second":
			if tk.LastUsedAt != "" {
				t.Fatalf("untouched token got last_used_at=%q", tk.LastUsedAt)
			}
		}
	}
	// Another user cannot revoke this token: it is not theirs.
	if rec := do(t, s, "DELETE", "/api/v1/tokens/"+firstID, "pat-iso-thief@example.test", "", nil); rec.Code != 404 {
		t.Fatalf("foreign user revoke: got %d, want 404", rec.Code)
	}
	// The owner can; the thief's attempt above must not have done it.
	if rec := tokenReq(t, s, "DELETE", "/api/v1/tokens/"+firstID, secondSecret, nil); rec.Code != 204 {
		t.Fatalf("owner revoke: got %d: %s", rec.Code, rec.Body)
	}
}

// TestTokenRequiresLabel: an unnamed token is unrecoverable in the list, so
// the daemon refuses it.
func TestTokenRequiresLabel(t *testing.T) {
	s := testServer(t)
	rec := do(t, s, "POST", "/api/v1/tokens", "pat-nolabel@example.test", "", map[string]string{"label": "  "})
	if rec.Code != 400 {
		t.Fatalf("blank label: got %d, want 400", rec.Code)
	}
}

// TestPatchHost covers the post-creation edit surface: keepalive and
// endpoint change, and switching the invited consumer.
func TestPatchHost(t *testing.T) {
	s := testServer(t)
	owner := "patch-owner@example.test"
	c1 := "patch-consumer-one@example.test"
	c2 := "patch-consumer-two@example.test"

	ids := map[string]string{}
	for _, sub := range []string{owner, c1, c2} {
		rec := do(t, s, "GET", "/api/v1/me", sub, "", nil)
		if rec.Code != 200 {
			t.Fatalf("provision %s: %d", sub, rec.Code)
		}
		var me struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &me)
		ids[sub] = me.ID
	}

	in := map[string]any{
		"name":          "patch-" + strconv.FormatInt(time.Now().UnixNano(), 36),
		"wg_public_key": "a2tra2tra2tra2tra2tra2tra2tra2tra2tra2tra2s=",
		"transport":     "wireguard",
		"consumer_id":   ids[c1],
	}
	rec := do(t, s, "POST", "/api/v1/hosts", owner, "", in)
	if rec.Code != 200 && rec.Code != 201 {
		t.Fatalf("create host: got %d: %s", rec.Code, rec.Body)
	}
	var h struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &h)
	path := "/api/v1/hosts/" + h.ID
	t.Cleanup(func() { do(t, s, "DELETE", path, owner, "", nil) })

	// The first consumer registers their BYOK key so the switch below has
	// something to actually invalidate.
	if rec := do(t, s, "POST", path+"/consumer-key", c1, "",
		map[string]string{"wg_public_key": "a2tra2tra2tra2tra2tra2tra2tra2tra2tra2tra2s="}); rec.Code != 204 {
		t.Fatalf("register consumer key: got %d: %s", rec.Code, rec.Body)
	}

	// Stranger and the consumers themselves may not patch: only the owner
	// (or an admin) edits the host.
	for _, sub := range []string{"patch-stranger@example.test", c1, c2} {
		if rec := do(t, s, "PATCH", path, sub, "",
			map[string]any{"keepalive": 10}); rec.Code != 403 && rec.Code != 404 {
			t.Fatalf("non-owner %s patch: got %d", sub, rec.Code)
		}
	}
	// Validation: out-of-range keepalive, consumer equal to the owner,
	// unknown consumer.
	if rec := do(t, s, "PATCH", path, owner, "",
		map[string]any{"keepalive": -1}); rec.Code != 400 {
		t.Fatalf("negative keepalive: got %d, want 400", rec.Code)
	}
	if rec := do(t, s, "PATCH", path, owner, "",
		map[string]any{"consumer_id": ids[owner]}); rec.Code != 400 {
		t.Fatalf("consumer == owner: got %d, want 400", rec.Code)
	}
	if rec := do(t, s, "PATCH", path, owner, "",
		map[string]any{"consumer_id": "00000000-0000-0000-0000-000000000000"}); rec.Code != 404 {
		t.Fatalf("unknown consumer: got %d, want 404", rec.Code)
	}
	// Owner changes keepalive + endpoint + consumer in one call.
	rec = do(t, s, "PATCH", path, owner, "", map[string]any{
		"keepalive":   10,
		"endpoint":    "home.example.test:51820",
		"consumer_id": ids[c2],
	})
	if rec.Code != 200 {
		t.Fatalf("owner patch: got %d: %s", rec.Code, rec.Body)
	}
	var patched struct {
		Keepalive           int     `json:"keepalive"`
		Endpoint            string  `json:"endpoint"`
		ConsumerID          string  `json:"consumer_id"`
		ConsumerWGPublicKey *string `json:"consumer_wg_public_key"`
		ConsumerTunnelIPv4  *string `json:"consumer_tunnel_ipv4"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &patched); err != nil {
		t.Fatal(err)
	}
	if patched.Keepalive != 10 || patched.Endpoint != "home.example.test:51820" || patched.ConsumerID != ids[c2] {
		t.Fatalf("patch not applied: %+v", patched)
	}
	// Security invariant: the outgoing consumer's key material must be gone,
	// otherwise they keep a live peer on the gateway with the shared PSK.
	if patched.ConsumerWGPublicKey != nil || patched.ConsumerTunnelIPv4 != nil {
		t.Fatalf("consumer key/IP survived the switch: %+v", patched)
	}
}

// TestListUsersSearch: the invitation picker needs a filtered directory.
func TestListUsersSearch(t *testing.T) {
	s := testServer(t)
	// Provision a known user, then find them by substring.
	_ = do(t, s, "GET", "/api/v1/me", "directory-target@example.test", "", nil)
	rec := do(t, s, "GET", "/api/v1/users?q=directory-target", "someone@example.test", "", nil)
	if rec.Code != 200 {
		t.Fatalf("list users: got %d: %s", rec.Code, rec.Body)
	}
	var us []struct {
		DisplayName string `json:"display_name"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &us); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, u := range us {
		if u.DisplayName == "directory-target@example.test" {
			found = true
		}
	}
	if !found {
		t.Fatalf("search missed the provisioned user: %+v", us)
	}
	// Empty result is [] and not null.
	rec = do(t, s, "GET", "/api/v1/users?q=definitely-no-such-user-xyz", "someone@example.test", "", nil)
	if rec.Code != 200 || rec.Body.String() != "[]\n" {
		t.Fatalf("empty users: got %d %q", rec.Code, rec.Body.String())
	}
}

// TestEventsScoping: a regular user sees only their own audit trail, while an
// admin reads the full feed. The negative case matters: a second user's event
// must be invisible, otherwise a missing WHERE clause would pass silently.
func TestEventsScoping(t *testing.T) {
	s := testServer(t)
	mine := "events-mine@example.test"
	other := "events-other@example.test"

	// Generate one event per user.
	if rec := do(t, s, "POST", "/api/v1/tokens", mine, "", map[string]string{"label": "evt-mine"}); rec.Code != 200 {
		t.Fatalf("seed own token: got %d", rec.Code)
	}
	if rec := do(t, s, "POST", "/api/v1/tokens", other, "", map[string]string{"label": "evt-other"}); rec.Code != 200 {
		t.Fatalf("seed other token: got %d", rec.Code)
	}

	rec := do(t, s, "GET", "/api/v1/events?limit=500", mine, "", nil)
	if rec.Code != 200 {
		t.Fatalf("own events: got %d: %s", rec.Code, rec.Body)
	}
	var own []struct {
		Action string          `json:"action"`
		Detail json.RawMessage `json:"detail"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &own); err != nil {
		t.Fatal(err)
	}
	if len(own) == 0 || own[0].Action != "token.create" {
		t.Fatalf("own event feed: %+v", own)
	}
	// Isolation: the other user's token.create must not appear in my feed.
	if bytes.Contains(rec.Body.Bytes(), []byte("evt-other")) {
		t.Fatal("own feed leaked another user's event")
	}
	// Admin sees both.
	rec = do(t, s, "GET", "/api/v1/events?limit=500", "", "correcthorse", nil)
	if rec.Code != 200 {
		t.Fatalf("admin events: got %d", rec.Code)
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte("evt-other")) {
		t.Fatal("admin feed is missing the other user's event")
	}
}

// TestReconcileTrigger: POST /reconcile answers with the queued flag.
func TestReconcileTrigger(t *testing.T) {
	s := testServer(t)
	rec := do(t, s, "POST", "/api/v1/reconcile", "trigger@example.test", "", nil)
	if rec.Code != 200 {
		t.Fatalf("reconcile: got %d: %s", rec.Code, rec.Body)
	}
	var out struct {
		Queued bool `json:"reconcile_queued"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || !out.Queued {
		t.Fatalf("reconcile response: %s", rec.Body)
	}
}

// TestHostAddressPinning covers the operator-facing half of the new
// addressing model: a pinned address/port is honoured (so a peer keeps a
// memorable number), the reserved gateway block is rejected, and a taken
// pin fails loudly instead of silently landing on another peer's address.
func TestHostAddressPinning(t *testing.T) {
	s := testServer(t)
	owner := "pin-owner-" + strconv.FormatInt(time.Now().UnixNano(), 36) + "@example.test"
	consumerSub := "pin-consumer-" + strconv.FormatInt(time.Now().UnixNano(), 36) + "@example.test"

	rec := do(t, s, "GET", "/api/v1/me", consumerSub, "", nil)
	if rec.Code != 200 {
		t.Fatalf("provision consumer: %d", rec.Code)
	}
	var consumer struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &consumer)

	// Pick a free octet and port: the smoke database is shared with the client
	// integration test and keeps rows from earlier runs, so a hard-coded pin
	// would flake on a parallel package run.
	usedIP, usedPort := map[string]bool{}, map[string]bool{}
	rec = do(t, s, "GET", "/api/v1/hosts", "", "correcthorse", nil)
	var existing []struct {
		TunnelIPv4 string `json:"tunnel_ipv4"`
		ListenPort int    `json:"listen_port"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &existing)
	for _, h := range existing {
		usedIP[h.TunnelIPv4] = true
		usedPort[strconv.Itoa(h.ListenPort)] = true
	}
	octet, port := 0, 0
	for i := 2; i < 200; i++ {
		if !usedIP["10.66.66."+strconv.Itoa(i)+"/32"] && !usedPort[strconv.Itoa(20000+i)] {
			octet, port = i, 20000+i
			break
		}
	}
	if octet == 0 {
		t.Fatal("no free octet in the smoke database")
	}
	suffix := strconv.Itoa(octet)
	create := func(name string, body map[string]any) *httptest.ResponseRecorder {
		body["name"] = name
		body["wg_public_key"] = "a2tra2tra2tra2tra2tra2tra2tra2tra2tra2tra2s="
		body["transport"] = "wireguard"
		body["consumer_id"] = consumer.ID
		return do(t, s, "POST", "/api/v1/hosts", owner, "", body)
	}

	// Pinned pair is honoured exactly.
	rec = create("pin-a-"+suffix, map[string]any{
		"preferred_ipv4": "10.66.66." + strconv.Itoa(octet),
		"preferred_ipv6": "fd66:66::" + strconv.FormatInt(int64(octet), 16),
		"preferred_port": port,
	})
	if rec.Code != 200 && rec.Code != 201 {
		t.Fatalf("create pinned host: %d: %s", rec.Code, rec.Body)
	}
	var pinned struct {
		ID         string `json:"id"`
		TunnelIPv4 string `json:"tunnel_ipv4"`
		TunnelIPv6 string `json:"tunnel_ipv6"`
		ListenPort int    `json:"listen_port"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &pinned); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { do(t, s, "DELETE", "/api/v1/hosts/"+pinned.ID, owner, "", nil) })
	wantV4 := "10.66.66." + strconv.Itoa(octet) + "/32"
	wantV6 := "fd66:66::" + strconv.FormatInt(int64(octet), 16) + "/128"
	if pinned.TunnelIPv4 != wantV4 || pinned.TunnelIPv6 != wantV6 || pinned.ListenPort != port {
		t.Fatalf("pin not honoured: %+v", pinned)
	}

	// Same pin again must fail: two peers cannot share an address/port on a node.
	if rec := create("pin-b-"+suffix, map[string]any{
		"preferred_ipv4": "10.66.66." + strconv.Itoa(octet), "preferred_port": port + 1,
	}); rec.Code < 400 {
		t.Fatalf("duplicate pinned address accepted: %d %s", rec.Code, rec.Body)
	}
	if rec := create("pin-c-"+suffix, map[string]any{
		"preferred_port": port,
	}); rec.Code < 400 {
		t.Fatalf("duplicate pinned port accepted: %d %s", rec.Code, rec.Body)
	}
	// The gateway itself is reserved: .1 must be refused.
	if rec := create("pin-d-"+suffix, map[string]any{
		"preferred_ipv4": "10.66.66.1",
	}); rec.Code < 400 {
		t.Fatalf("reserved gateway address accepted: %d %s", rec.Code, rec.Body)
	}
	// An address outside the transport's network is refused.
	if rec := create("pin-e-"+suffix, map[string]any{
		"preferred_ipv4": "10.99.99.16",
	}); rec.Code < 400 {
		t.Fatalf("out-of-network address accepted: %d %s", rec.Code, rec.Body)
	}
}
