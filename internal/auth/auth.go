package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"
	"nadamu/dyatel/internal/config"
	"nadamu/dyatel/internal/store"
)

const (
	SubclaimHeader = "X-Dyatel-Sub"
	roleOwner      = "owner"
	roleConsumer   = "consumer"
	roleAdmin      = "admin"
)

// HashToken derives the lookup digest of a PAT. A 256-bit random secret has
// no dictionary to attack, so a plain SHA-256 is the right tool: argon2id
// here would buy nothing and cost 64 MiB + tens of milliseconds on every
// request. Lookup is by exact digest, which is why a per-token salt is not
// an option — the digest must be searchable.
func HashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// NewToken mints a PAT: dyatel_<43 b64url chars>.
func NewToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return "dyatel_" + base64.RawURLEncoding.EncodeToString(b)
}

// Identity is the authenticated caller.
type Identity struct {
	User       *store.User
	AuthMethod string // oidc | pat | fallback
	IsAdmin    bool
}

func (i Identity) CanSeeHost(h store.Host) bool {
	if i.IsAdmin {
		return true
	}
	return h.OwnerID == i.User.ID || h.ConsumerID == i.User.ID
}

func (i Identity) RoleOn(h store.Host) string {
	switch {
	case i.IsAdmin:
		return roleAdmin
	case h.OwnerID == i.User.ID:
		return roleOwner
	case h.ConsumerID == i.User.ID:
		return roleConsumer
	}
	return ""
}

type oidcUserSync interface {
	CreateUser(ctx context.Context, sub, name string) (*store.User, error)
	SetAdmin(ctx context.Context, id uuid.UUID, admin bool) error
}

// Authenticator validates PAT / fallback / OIDC-sub requests.
// The public front (nginx) terminates TLS; OIDC bearer validation is
// delegated to Authentik via the configured userinfo or introspection endpoint.
type Authenticator struct {
	cfg   *config.Config
	st    *store.Store
	users oidcUserSync
	http  *http.Client
}

func New(cfg *config.Config, st *store.Store) *Authenticator {
	var users oidcUserSync
	if st != nil {
		users = st
	}
	return &Authenticator{
		cfg:   cfg,
		st:    st,
		users: users,
		http:  &http.Client{Timeout: 5 * time.Second},
	}
}

var anon = Identity{}

func (a *Authenticator) Authenticate(r *http.Request) (Identity, error) {
	// 1. Break-glass admin: Basic creds from env.
	if user, pass, ok := r.BasicAuth(); ok && a.cfg.FallbackAdminUser != "" {
		if user == a.cfg.FallbackAdminUser && verifyPHC(a.cfg.FallbackAdminHash, pass) {
			id, err := a.st.CreateUser(r.Context(), "fallback-admin", "Fallback Admin")
			if err != nil {
				return anon, err
			}
			_ = a.st.SetAdmin(r.Context(), id.ID, true)
			return Identity{User: id, AuthMethod: "fallback", IsAdmin: true}, nil
		}
	}

	// 2. OIDC bearer -> introspect at Authentik, then lazily provision.
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") && !strings.HasPrefix(strings.TrimPrefix(h, "Bearer "), "dyatel_") {
		return a.oidc(r, strings.TrimSpace(strings.TrimPrefix(h, "Bearer ")))
	}

	// 3. PAT.
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer dyatel_") {
		tok := strings.TrimPrefix(h, "Bearer ")
		row := a.st.Pool.QueryRow(r.Context(),
			`SELECT t.id, t.user_id, u.authentik_sub, u.display_name, u.is_admin
			 FROM tokens t JOIN users u ON u.id = t.user_id
			 WHERE t.secret_hash = $1 AND t.revoked_at IS NULL`, HashToken(tok))
		var tid, id, sub, name string
		var admin bool
		if err := row.Scan(&tid, &id, &sub, &name, &admin); err != nil {
			return anon, fmt.Errorf("bad token")
		}
		uid := uuid.MustParse(id)
		a.st.TouchToken(r.Context(), uuid.MustParse(tid))
		return Identity{User: &store.User{ID: uid, AuthentikSub: sub, DisplayName: name, IsAdmin: admin},
			AuthMethod: "pat", IsAdmin: admin}, nil
	}

	// 4. Trusted-sub header (nginx auth_request / oauth2-proxy style).
	if sub := r.Header.Get(SubclaimHeader); sub != "" {
		u, err := a.st.CreateUser(r.Context(), sub, sub) // lazy provision
		if err != nil {
			return anon, err
		}
		return Identity{User: u, AuthMethod: "oidc", IsAdmin: a.checkAdminGroup(u)}, nil
	}

	return anon, fmt.Errorf("unauthenticated")
}

// oidc calls Authentik userinfo or introspection; falls through to error if
// Authentik is down (break-glass covers that outage).
func (a *Authenticator) oidc(r *http.Request, token string) (Identity, error) {
	if a.cfg.OIDCIntrospectionURL == "" {
		return anon, fmt.Errorf("OIDC not configured")
	}
	client := a.http
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}

	endpoint := strings.TrimRight(a.cfg.OIDCIntrospectionURL, "/")
	isUserInfo := strings.HasSuffix(endpoint, "/userinfo")

	var req *http.Request
	var err error
	if isUserInfo {
		req, err = http.NewRequestWithContext(r.Context(), http.MethodGet, a.cfg.OIDCIntrospectionURL, nil)
		if err != nil {
			return anon, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
	} else {
		form := url.Values{
			"token":         {token},
			"client_id":     {a.cfg.OIDCClientID},
			"client_secret": {a.cfg.OIDCClientSecret},
		}
		req, err = http.NewRequestWithContext(r.Context(), http.MethodPost, a.cfg.OIDCIntrospectionURL, strings.NewReader(form.Encode()))
		if err != nil {
			return anon, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	resp, err := client.Do(req)
	if err != nil {
		return anon, fmt.Errorf("authentik unreachable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return anon, fmt.Errorf("invalid token")
	}

	var out struct {
		Active            bool     `json:"active"`
		Sub               string   `json:"sub"`
		Name              string   `json:"name"`
		PreferredUsername string   `json:"preferred_username"`
		Groups            []string `json:"groups"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return anon, fmt.Errorf("invalid token")
	}
	if (!isUserInfo && !out.Active) || out.Sub == "" {
		return anon, fmt.Errorf("invalid token")
	}

	name := out.Name
	if name == "" {
		name = out.PreferredUsername
	}
	if name == "" {
		name = out.Sub
	}
	u, err := a.users.CreateUser(r.Context(), out.Sub, name)
	if err != nil {
		return anon, err
	}
	admin := false
	for _, g := range out.Groups {
		if g == a.cfg.AuthentikAdminGroup {
			admin = true
		}
	}
	if u.IsAdmin != admin {
		_ = a.users.SetAdmin(r.Context(), u.ID, admin)
		u.IsAdmin = admin
	}
	return Identity{User: u, AuthMethod: "oidc", IsAdmin: admin}, nil
}

func (a *Authenticator) checkAdminGroup(u *store.User) bool {
	// Group sync for trusted-header auth happens on OIDC login only; here we
	// trust the DB flag which the OIDC flow maintains.
	return u.IsAdmin
}

// verifyPHC checks an argon2id PHC string against a password.
// Format: $argon2id$v=19$m=65536,t=2,p=1$<b64salt>$<b64hash>
func verifyPHC(phc, pass string) bool {
	parts := strings.Split(phc, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return subtle.ConstantTimeCompare([]byte(phc), []byte(pass)) == 1
	}
	var v, m, t, p uint32
	if _, err := fmt.Sscanf(parts[2], "v=%d", &v); err != nil || v != 19 {
		return false
	}
	for _, kv := range strings.Split(parts[3], ",") {
		var n uint32
		switch {
		case strings.HasPrefix(kv, "m="):
			if _, err := fmt.Sscanf(kv, "m=%d", &n); err != nil {
				return false
			}
			m = n
		case strings.HasPrefix(kv, "t="):
			if _, err := fmt.Sscanf(kv, "t=%d", &n); err != nil {
				return false
			}
			t = n
		case strings.HasPrefix(kv, "p="):
			if _, err := fmt.Sscanf(kv, "p=%d", &n); err != nil {
				return false
			}
			p = n
		}
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(pass), salt, t, m, uint8(p), uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// Remove unused time import check when time.Second is used directly.
