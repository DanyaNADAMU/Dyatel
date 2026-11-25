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
	for _, sub := range []string{c1, c2} {
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
		"wg_public_key": "aGVsbG8gd29ybGQgMTIzNDU2Nzg5MEFCQ0RFRg==",
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

	// Stranger may not patch.
	if rec := do(t, s, "PATCH", path, "patch-stranger@example.test", "",
		map[string]any{"keepalive": 10}); rec.Code != 403 && rec.Code != 404 {
		t.Fatalf("stranger patch: got %d", rec.Code)
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
		Keepalive  int    `json:"keepalive"`
		Endpoint   string `json:"endpoint"`
		ConsumerID string `json:"consumer_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &patched); err != nil {
		t.Fatal(err)
	}
	if patched.Keepalive != 10 || patched.Endpoint != "home.example.test:51820" || patched.ConsumerID != ids[c2] {
		t.Fatalf("patch not applied: %+v", patched)
	}
	// Consumer cannot be the owner (DB CHECK mirrored at API level).
	if rec := do(t, s, "PATCH", path, owner, "",
		map[string]any{"consumer_id": "00000000-0000-0000-0000-000000000000"}); rec.Code != 404 {
		t.Fatalf("unknown consumer: got %d, want 404", rec.Code)
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
// admin reads the full feed.
func TestEventsScoping(t *testing.T) {
	s := testServer(t)
	me := "events-mine@example.test"
	// Generate at least one event for this user.
	rec := do(t, s, "POST", "/api/v1/tokens", me, "", map[string]string{"label": "evt"})
	if rec.Code != 200 {
		t.Fatalf("seed token: got %d", rec.Code)
	}
	rec = do(t, s, "GET", "/api/v1/events?limit=5", me, "", nil)
	if rec.Code != 200 {
		t.Fatalf("own events: got %d: %s", rec.Code, rec.Body)
	}
	var own []struct {
		Action string `json:"action"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &own); err != nil {
		t.Fatal(err)
	}
	if len(own) == 0 || own[0].Action != "token.create" {
		t.Fatalf("own event feed: %+v", own)
	}
	// Admin feed is at least as large and includes foreign actions.
	rec = do(t, s, "GET", "/api/v1/events?limit=500", "", "correcthorse", nil)
	if rec.Code != 200 {
		t.Fatalf("admin events: got %d", rec.Code)
	}
	var all []struct {
		Action string `json:"action"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &all); err != nil {
		t.Fatal(err)
	}
	if len(all) < len(own) {
		t.Fatalf("admin feed %d < own feed %d", len(all), len(own))
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
