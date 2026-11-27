package client

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The canned JSON below reproduces the daemon's exact wire shape: store.Host
// is serialized without json tags, so keys are Go field names and the
// []byte Params field arrives base64-encoded. Any drift in the daemon or in
// the client structs shows up right here.

// Wire fixtures pin the daemon's canonical snake_case json contract.
const cannedHost = `{"id":"6ba7b810-9dad-11d1-80b4-00c04fd430c8","name":"mc","node":"berg",` +
	`"owner_id":"6ba7b811-9dad-11d1-80b4-00c04fd430c8","consumer_id":"6ba7b812-9dad-11d1-80b4-00c04fd430c8",` +
	`"wg_public_key":"QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWY=","wg_pre_shared_key":"","gw_private_key":"",` +
	`"gw_public_key":"R0dQVUJL","tunnel_ipv4":"10.13.36.2/32","tunnel_ipv6":"fd00:36::2/128",` +
	`"consumer_wg_public_key":null,"consumer_tunnel_ipv4":null,"consumer_tunnel_ipv6":null,"endpoint":null,` +
	`"transport":"amneziawg","listen_port":51901,"params":"eyJqYyI6NH0=","keepalive":25,"state":"active"}`

const cannedForward = `{"id":"6ba7b814-9dad-11d1-80b4-00c04fd430c8",` +
	`"host_id":"6ba7b810-9dad-11d1-80b4-00c04fd430c8","public_port":25565,"target_port":25565,` +
	`"proto":"tcp","label":"minecraft"}`

const cannedMe = `{"id":"6ba7b811-9dad-11d1-80b4-00c04fd430c8","sub":"owner@example.test",` +
	`"name":"Owner","is_admin":true,"auth":"pat"}`

// newTestDaemon starts an httptest server that answers a fixed route table
// with canned payloads and records what the client actually sent, so tests
// can pin both the paths and the auth headers.
func newTestDaemon(t *testing.T) (*Client, *recorder) {
	t.Helper()
	rec := &recorder{}
	mux := http.NewServeMux()
	handle := func(path string, status int, body string) {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			rec.path = r.URL.Path
			rec.method = r.Method
			rec.auth = r.Header.Get("Authorization")
			rec.basicUser, rec.basicPass, _ = r.BasicAuth()
			rec.body = readAll(r)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
		})
	}
	handle("/api/v1/me", 200, cannedMe)
	handle("/api/v1/status", 200, `{"checked":true}`)
	// Same path as the daemon's POST/GET pair: GET returns the list, POST
	// returns one host, mirroring the real route table.
	mux.HandleFunc("/api/v1/hosts/", func(w http.ResponseWriter, r *http.Request) {
		rec.path = r.URL.Path
		rec.method = r.Method
		rec.auth = r.Header.Get("Authorization")
		rec.basicUser, rec.basicPass, _ = r.BasicAuth()
		rec.body = readAll(r)
		w.Header().Set("Content-Type", "application/json")
		body := "[" + cannedHost + "]"
		if r.Method == http.MethodPost {
			body = cannedHost
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte(body))
	})
	handle("/api/v1/hosts/6ba7b810-9dad-11d1-80b4-00c04fd430c8/", 200, cannedHost)
	handle("/api/v1/hosts/6ba7b810-9dad-11d1-80b4-00c04fd430c8/forwards", 200, "["+cannedForward+"]")
	handle("/api/v1/hosts/6ba7b810-9dad-11d1-80b4-00c04fd430c8/dns", 200, `[{"id":"d1","forward_id":"f1","name":"mc1.test.nada.mu","created_at":"2026-11-27T00:00:00Z"}]`)
	handle("/api/v1/forwards/f1/dns", 200, `{"id":"d1","forward_id":"f1","name":"mc1.test.nada.mu","created_at":"2026-11-27T00:00:00Z"}`)
	handle("/api/v1/hosts/6ba7b810-9dad-11d1-80b4-00c04fd430c8/config/client", 200, "[Interface]\nPrivateKey = ...\n")
	handle("/api/v1/hosts/new/forwards", 200, cannedForward)
	handle("/api/v1/hosts/new/", 200, cannedHost)
	handle("/api/v1/unauthorized", 401, "401: unauthenticated\n")
	handle("/api/v1/forbidden", 403, "403\n")
	handle("/api/v1/badrequest", 400, "400: bad name (a-z0-9-)\n")
	handle("/api/v1/precondition", 412, "412: consumer key not registered\n")

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	cl := New(srv.URL, "dyatel_testtoken", "", "")
	return cl, rec
}

type recorder struct {
	path, method, auth   string
	basicUser, basicPass string
	body                 string
}

func readAll(r *http.Request) string {
	b, _ := io.ReadAll(r.Body)
	return string(b)
}

func TestMe(t *testing.T) {
	cl, rec := newTestDaemon(t)
	me, err := cl.Me()
	if err != nil {
		t.Fatalf("me: %v", err)
	}
	if me.ID == "" || me.Sub != "owner@example.test" || !me.IsAdmin || me.Auth != "pat" {
		t.Fatalf("me decode: %+v", me)
	}
	if rec.path != "/api/v1/me" {
		t.Fatalf("path: %s", rec.path)
	}
	if rec.auth != "Bearer dyatel_testtoken" {
		t.Fatalf("auth header: %q", rec.auth)
	}
}

// TestBasicAuthAndBearerWins: Basic creds are used when no token is set,
// and a token overrides them when both are configured.
func TestBasicAuthAndBearerWins(t *testing.T) {
	_, rec := newTestDaemon(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.auth = r.Header.Get("Authorization")
		fmt.Fprint(w, cannedMe)
	}))
	t.Cleanup(srv.Close)

	basic := New(srv.URL, "", "breakglass", "correcthorse")
	if _, err := basic.Me(); err != nil {
		t.Fatal(err)
	}
	if rec.auth == "" || !strings.HasPrefix(rec.auth, "Basic ") {
		t.Fatalf("basic auth not sent: %q", rec.auth)
	}

	both := New(srv.URL, "dyatel_testtoken", "breakglass", "correcthorse")
	if _, err := both.Me(); err != nil {
		t.Fatal(err)
	}
	if rec.auth != "Bearer dyatel_testtoken" {
		t.Fatalf("bearer must win over basic, got %q", rec.auth)
	}
}

// TestHostWireFieldNames pins the untagged-store serialization: PascalCase
// keys and base64-wrapped Params must decode into the client structs.
func TestHostWireFieldNames(t *testing.T) {
	cl, _ := newTestDaemon(t)
	hs, err := cl.ListHosts()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(hs) != 1 {
		t.Fatalf("want 1 host, got %d", len(hs))
	}
	h := hs[0]
	if h.Name != "mc" || h.Transport != "amneziawg" || h.ListenPort != 51901 || h.Keepalive != 25 || h.State != "active" {
		t.Fatalf("host decode: %+v", h)
	}
	if h.Endpoint != nil || h.ConsumerWGPublicKey != nil {
		t.Fatalf("nullable fields must stay nil: %+v", h)
	}
	params, err := h.DecodedParams()
	if err != nil {
		t.Fatalf("decoded params: %v", err)
	}
	var decoded struct {
		Jc int `json:"jc"`
	}
	if err := json.Unmarshal(params, &decoded); err != nil || decoded.Jc != 4 {
		t.Fatalf("params must decode to {jc:4}, got %s (%v)", params, err)
	}
}

func TestDecodedParamsPassthrough(t *testing.T) {
	// A future daemon that tags Params as raw JSON must keep working.
	h := Host{Params: json.RawMessage(`{"jc":4}`)}
	params, err := h.DecodedParams()
	if err != nil || string(params) != `{"jc":4}` {
		t.Fatalf("raw object passthrough: %s %v", params, err)
	}
	if _, err := (Host{}).DecodedParams(); err != nil {
		t.Fatalf("empty params: %v", err)
	}
}

func TestGetHostAndForwards(t *testing.T) {
	cl, rec := newTestDaemon(t)
	h, err := cl.GetHost("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
	if err != nil {
		t.Fatal(err)
	}
	if h.ID == "" {
		t.Fatal("empty host")
	}
	fs, err := cl.ListForwards(h.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || fs[0].PublicPort != 25565 || fs[0].Proto != "tcp" || fs[0].Label != "minecraft" {
		t.Fatalf("forwards decode: %+v", fs)
	}
	if rec.path != "/api/v1/hosts/6ba7b810-9dad-11d1-80b4-00c04fd430c8/forwards" {
		t.Fatalf("forwards path: %s", rec.path)
	}
	ds, err := cl.ListHostDNS(h.ID)
	if err != nil || len(ds) != 1 || ds[0].Name != "mc1.test.nada.mu" {
		t.Fatalf("list host dns: %v %+v", err, ds)
	}
	d, err := cl.SetForwardDNS("f1", "mc1")
	if err != nil || d.Name != "mc1.test.nada.mu" {
		t.Fatalf("set forward dns: %v %+v", err, d)
	}
	if err := cl.DeleteForwardDNS("f1"); err != nil {
		t.Fatalf("delete forward dns: %v", err)
	}
}

// TestCreateAndMutations checks the request bodies the client sends and the
// silent (204-style) mutations.
func TestCreateAndMutations(t *testing.T) {
	cl, rec := newTestDaemon(t)

	h, err := cl.CreateHost(CreateHostRequest{
		Name: "mc", Transport: "amneziawg", ConsumerID: "6ba7b812-9dad-11d1-80b4-00c04fd430c8",
		Keepalive: 25, Params: json.RawMessage(`{"jc":4}`),
	})
	if err != nil || h.Name != "mc" {
		t.Fatalf("create: %v %+v", err, h)
	}
	if rec.method != http.MethodPost || rec.path != "/api/v1/hosts/" {
		t.Fatalf("create request: %s %s", rec.method, rec.path)
	}
	var sent map[string]any
	if err := json.Unmarshal([]byte(rec.body), &sent); err != nil {
		t.Fatalf("create body: %s (%v)", rec.body, err)
	}
	if sent["name"] != "mc" || sent["transport"] != "amneziawg" ||
		sent["consumer_id"] != "6ba7b812-9dad-11d1-80b4-00c04fd430c8" {
		t.Fatalf("create payload: %v", sent)
	}
	params, ok := sent["params"].(map[string]any)
	if !ok || params["jc"].(float64) != 4 {
		t.Fatalf("params must ride as raw json, got %v", sent["params"])
	}

	f, err := cl.CreateForward("new", CreateForwardRequest{PublicPort: 25565, TargetPort: 25565, Proto: "tcp", Label: "mc"})
	if err != nil || f.PublicPort != 25565 {
		t.Fatalf("create forward: %v %+v", err, f)
	}
	var fsent map[string]any
	if err := json.Unmarshal([]byte(rec.body), &fsent); err != nil {
		t.Fatal(err)
	}
	if fsent["public_port"].(float64) != 25565 || fsent["proto"] != "tcp" {
		t.Fatalf("forward payload: %v", fsent)
	}

	// Mutations that answer 204: the daemon writes no body, client must
	// treat that as success.
	steps := []struct {
		name string
		fn   func() error
	}{
		{"delete host", func() error { return cl.DeleteHost("new") }},
		{"set state", func() error { return cl.SetState("new", "suspended") }},
		{"register consumer", func() error { return cl.RegisterConsumerKey("new", strings.Repeat("A", 44)) }},
		{"delete forward", func() error { return cl.DeleteForward("new", "6ba7b814-9dad-11d1-80b4-00c04fd430c8") }},
	}
	for _, step := range steps {
		if err := step.fn(); err != nil {
			t.Fatalf("%s: %v", step.name, err)
		}
		if rec.path == "/api/v1/hosts/new/consumer-key" {
			if got := rec.body; got != `{"wg_public_key":"`+strings.Repeat("A", 44)+`"}` {
				t.Fatalf("consumer key payload: %s", got)
			}
			if rec.auth != "Bearer dyatel_testtoken" {
				t.Fatalf("consumer key auth: %q", rec.auth)
			}
		}
	}
}

func TestClientConfigText(t *testing.T) {
	cl, _ := newTestDaemon(t)
	raw, err := cl.ClientConfig("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(raw), "[Interface]") {
		t.Fatalf("config text: %q", raw)
	}
}

// TestErrorSurfacing: non-2xx answers become *APIError carrying the
// daemon's plain-text body, which is what the CLI prints on stderr.
func TestErrorSurfacing(t *testing.T) {
	cl, _ := newTestDaemon(t)
	cases := []struct {
		path, want string
		status     int
	}{
		{"/unauthorized", "401: unauthenticated", 401},
		{"/forbidden", "403", 403},
		{"/badrequest", "400: bad name (a-z0-9-)", 400},
		{"/precondition", "412: consumer key not registered", 412},
	}
	for _, tc := range cases {
		_, err := cl.Do(http.MethodGet, tc.path, nil)
		apiErr, ok := err.(*APIError)
		if !ok {
			t.Fatalf("%s: want *APIError, got %v", tc.path, err)
		}
		if apiErr.Status != tc.status || !strings.Contains(apiErr.Error(), tc.want) {
			t.Fatalf("%s: got %q, want status %d with %q", tc.path, apiErr.Error(), tc.status, tc.want)
		}
	}
}
