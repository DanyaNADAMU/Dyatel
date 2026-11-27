package auth

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
	"nadamu/dyatel/internal/config"
	"nadamu/dyatel/internal/store"
)

type fakeUserSync struct {
	users map[string]*store.User
}

func (f *fakeUserSync) CreateUser(_ context.Context, sub, name string) (*store.User, error) {
	if f.users == nil {
		f.users = map[string]*store.User{}
	}
	if u, ok := f.users[sub]; ok {
		u.DisplayName = name
		copyU := *u
		return &copyU, nil
	}
	u := &store.User{
		ID:           uuid.New(),
		AuthentikSub: sub,
		DisplayName:  name,
	}
	f.users[sub] = u
	copyU := *u
	return &copyU, nil
}

func (f *fakeUserSync) SetAdmin(_ context.Context, id uuid.UUID, admin bool) error {
	for _, u := range f.users {
		if u.ID == id {
			u.IsAdmin = admin
		}
	}
	return nil
}

func TestHashTokenAndNewToken(t *testing.T) {
	t1 := NewToken()
	t2 := NewToken()
	if !strings.HasPrefix(t1, "dyatel_") {
		t.Fatalf("unexpected token prefix: %q", t1)
	}
	if len(t1) != len("dyatel_")+43 {
		t.Fatalf("unexpected token length %d: %q", len(t1), t1)
	}
	if t1 == t2 {
		t.Fatal("two minted tokens collided")
	}

	d1 := HashToken(t1)
	d2 := HashToken(t1)
	if !slices.Equal(d1, d2) {
		t.Fatal("HashToken is not deterministic")
	}
	if len(d1) != sha256.Size {
		t.Fatalf("digest len = %d, want %d", len(d1), sha256.Size)
	}
	if slices.Equal(d1, HashToken(t2)) {
		t.Fatal("different tokens produced identical digests")
	}
}

func TestVerifyPHC(t *testing.T) {
	// Test hash from api_test.go for password "correcthorse".
	const phc = "$argon2id$v=19$m=65536,t=2,p=1$0Zh50ymKo7qzu6LzLbJbyw$++EE7ecjdmShgjkPBEIKolDFe0PuLkQ5OqyZrqUmhL0"

	if !verifyPHC(phc, "correcthorse") {
		t.Fatal("valid password rejected")
	}
	if verifyPHC(phc, "wrongpass") {
		t.Fatal("wrong password accepted")
	}
	if verifyPHC("$argon2id$v=18$m=65536,t=2,p=1$0Zh50ymKo7qzu6LzLbJbyw$++EE", "correcthorse") {
		t.Fatal("unsupported argon2 version accepted")
	}
	if verifyPHC("$argon2id$v=19$m=65536,t=2,p=1$%%%$++EE", "correcthorse") {
		t.Fatal("invalid base64 salt accepted")
	}
	if !verifyPHC("plain-secret", "plain-secret") || verifyPHC("plain-secret", "other") {
		t.Fatal("constant-time fallback comparison failed")
	}
}

func TestIdentityVisibilityAndRole(t *testing.T) {
	ownerID := uuid.New()
	consumerID := uuid.New()
	strangerID := uuid.New()
	host := store.Host{OwnerID: ownerID, ConsumerID: consumerID}

	cases := []struct {
		name string
		id   Identity
		see  bool
		role string
	}{
		{"admin", Identity{User: &store.User{ID: strangerID}, IsAdmin: true}, true, roleAdmin},
		{"owner", Identity{User: &store.User{ID: ownerID}}, true, roleOwner},
		{"consumer", Identity{User: &store.User{ID: consumerID}}, true, roleConsumer},
		{"stranger", Identity{User: &store.User{ID: strangerID}}, false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.id.CanSeeHost(host); got != tc.see {
				t.Fatalf("CanSeeHost = %v, want %v", got, tc.see)
			}
			if got := tc.id.RoleOn(host); got != tc.role {
				t.Fatalf("RoleOn = %q, want %q", got, tc.role)
			}
		})
	}
}

func TestOIDCUserInfoAndGroupSync(t *testing.T) {
	var groups []string
	var name string
	var preferUser string
	var status int

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/application/o/userinfo/" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != http.MethodGet {
			t.Fatalf("expected GET for userinfo, got %s", r.Method)
		}
		if r.Header.Get("Authorization") != "Bearer good-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if status != 0 && status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sub":                "sub-123",
			"name":               name,
			"preferred_username": preferUser,
			"groups":             groups,
		})
	}))
	defer srv.Close()

	users := &fakeUserSync{}
	a := New(&config.Config{
		OIDCIntrospectionURL: srv.URL + "/application/o/userinfo/",
		AuthentikAdminGroup:  "authentik Admins",
	}, nil)
	a.users = users

	// Admin group membership promotes the user.
	name = "Danya"
	groups = []string{"Members", "authentik Admins"}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	req.Header.Set("Authorization", "Bearer good-token")
	id, err := a.Authenticate(req)
	if err != nil {
		t.Fatalf("userinfo auth failed: %v", err)
	}
	if !id.IsAdmin || id.AuthMethod != "oidc" || id.User.DisplayName != "Danya" {
		t.Fatalf("unexpected identity: %+v (%+v)", id, id.User)
	}

	// Removal from admin group demotes on next check and falls back to preferred_username.
	name = ""
	preferUser = "danya"
	groups = []string{"Members"}
	id, err = a.Authenticate(req)
	if err != nil {
		t.Fatalf("userinfo demote check failed: %v", err)
	}
	if id.IsAdmin || id.User.DisplayName != "danya" {
		t.Fatalf("expected demotion + preferred_username fallback, got %+v (%+v)", id, id.User)
	}

	// Bad bearer token rejected.
	badReq := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	badReq.Header.Set("Authorization", "Bearer bad-token")
	if _, err := a.Authenticate(badReq); err == nil {
		t.Fatal("expected bad token rejection")
	}
}

func TestOIDCIntrospectionCompat(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST for introspect, got %s", r.Method)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if r.Form.Get("client_id") != "dyatel" || r.Form.Get("client_secret") != "s3cr3t" {
			t.Fatalf("unexpected client creds: %v", r.Form)
		}
		active := r.Form.Get("token") == "active-tok"
		_ = json.NewEncoder(w).Encode(map[string]any{
			"active": active,
			"sub":    "sub-456",
			"name":   "Alice",
			"groups": []string{"authentik Admins"},
		})
	}))
	defer srv.Close()

	a := New(&config.Config{
		OIDCIntrospectionURL: srv.URL + "/application/o/introspect/",
		OIDCClientID:         "dyatel",
		OIDCClientSecret:     "s3cr3t",
		AuthentikAdminGroup:  "authentik Admins",
	}, nil)
	a.users = &fakeUserSync{}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	req.Header.Set("Authorization", "Bearer active-tok")
	id, err := a.Authenticate(req)
	if err != nil || !id.IsAdmin || id.User.DisplayName != "Alice" {
		t.Fatalf("introspect auth got (%+v, %v)", id, err)
	}

	inactiveReq := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	inactiveReq.Header.Set("Authorization", "Bearer inactive-tok")
	if _, err := a.Authenticate(inactiveReq); err == nil {
		t.Fatal("expected inactive token rejection")
	}
}
