package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrNotFound = errors.New("not found")

type Store struct {
	Pool *pgxpool.Pool
}

func Open(ctx context.Context, dsn string) (*Store, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		return nil, err
	}
	return &Store{Pool: pool}, nil
}

type User struct {
	ID uuid.UUID `json:"id"`
	// AuthentikSub is an internal identity key: it never rides the wire,
	// so a leaked API response cannot be replayed against Authentik.
	AuthentikSub string `json:"-"`
	DisplayName  string `json:"display_name"`
	IsAdmin      bool   `json:"is_admin"`
}

// The daemon serializes Host/Forward directly, so these json tags ARE the
// public /api/v1 wire contract. Keep them in sync with web/src/types.ts and
// internal/client/client.go (no case-insensitive fallback exists in TS).
type Host struct {
	ID                  uuid.UUID `json:"id"`
	Name                string    `json:"name"`
	Node                string    `json:"node"`
	OwnerID             uuid.UUID `json:"owner_id"`
	ConsumerID          uuid.UUID `json:"consumer_id"`
	WGPublicKey         string    `json:"wg_public_key"`
	WGPreSharedKey      string    `json:"-"`
	GWPrivateKey        string    `json:"-"`
	GWPublicKey         string    `json:"gw_public_key"`
	TunnelIPv4          string    `json:"tunnel_ipv4"`
	TunnelIPv6          string    `json:"tunnel_ipv6"`
	ConsumerWGPublicKey *string   `json:"consumer_wg_public_key,omitempty"`
	ConsumerTunnelIPv4  *string   `json:"consumer_tunnel_ipv4,omitempty"`
	ConsumerTunnelIPv6  *string   `json:"consumer_tunnel_ipv6,omitempty"`
	Endpoint            *string   `json:"endpoint,omitempty"`
	Transport           string    `json:"transport"`
	ListenPort          int       `json:"listen_port"`
	Params              []byte    `json:"params,omitempty"`
	Keepalive           int       `json:"keepalive"`
	State               string    `json:"state"`
}

type Forward struct {
	ID         uuid.UUID `json:"id"`
	HostID     uuid.UUID `json:"host_id"`
	PublicPort int       `json:"public_port"`
	TargetPort int       `json:"target_port"`
	Proto      string    `json:"proto"`
	Label      string    `json:"label"`
}

func (s *Store) UserBySub(ctx context.Context, sub string) (*User, error) {
	return scanUser(s.Pool.QueryRow(ctx,
		`SELECT id, authentik_sub, display_name, is_admin FROM users WHERE authentik_sub=$1`, sub))
}

func (s *Store) UserByID(ctx context.Context, id uuid.UUID) (*User, error) {
	return scanUser(s.Pool.QueryRow(ctx,
		`SELECT id, authentik_sub, display_name, is_admin FROM users WHERE id=$1`, id))
}

func scanUser(r pgx.Row) (*User, error) {
	var u User
	err := r.Scan(&u.ID, &u.AuthentikSub, &u.DisplayName, &u.IsAdmin)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &u, err
}

func (s *Store) CreateUser(ctx context.Context, sub, name string) (*User, error) {
	u, err := scanUser(s.Pool.QueryRow(ctx,
		`INSERT INTO users (authentik_sub, display_name)
		 VALUES ($1,$2)
		 ON CONFLICT (authentik_sub) DO UPDATE SET display_name=EXCLUDED.display_name
		 RETURNING id, authentik_sub, display_name, is_admin`, sub, name))
	return u, err
}

func (s *Store) SetAdmin(ctx context.Context, id uuid.UUID, admin bool) error {
	_, err := s.Pool.Exec(ctx, `UPDATE users SET is_admin=$2 WHERE id=$1`, id, admin)
	return err
}

func (s *Store) Host(ctx context.Context, id uuid.UUID) (*Host, error) {
	return scanHost(s.Pool.QueryRow(ctx, hostCols+` WHERE id=$1`, id))
}

func (s *Store) HostByName(ctx context.Context, name string) (*Host, error) {
	return scanHost(s.Pool.QueryRow(ctx, hostCols+` WHERE name=$1`, name))
}

func (s *Store) Hosts(ctx context.Context) ([]Host, error) {
	return scanHosts(s.Pool.Query(ctx, hostCols+` ORDER BY created_at`))
}

// HostsByNode returns the hosts a given daemon node owns and reconciles.
func (s *Store) HostsByNode(ctx context.Context, node string) ([]Host, error) {
	return scanHosts(s.Pool.Query(ctx, hostCols+` WHERE node=$1 ORDER BY created_at`, node))
}

func (s *Store) HostsByUser(ctx context.Context, uid uuid.UUID) ([]Host, error) {
	return scanHosts(s.Pool.Query(ctx, hostCols+` WHERE owner_id=$1 OR consumer_id=$1 ORDER BY created_at`, uid))
}

const hostCols = `SELECT id, name, node, owner_id, consumer_id, wg_public_key, wg_preshared_key,
	gw_private_key, gw_public_key, tunnel_ipv4::text, tunnel_ipv6::text,
	consumer_wg_public_key, consumer_tunnel_ipv4::text, consumer_tunnel_ipv6::text,
	endpoint, transport, listen_port, params, keepalive, state FROM hosts`

func scanHost(r pgx.Row) (*Host, error) {
	var h Host
	err := r.Scan(&h.ID, &h.Name, &h.Node, &h.OwnerID, &h.ConsumerID, &h.WGPublicKey,
		&h.WGPreSharedKey, &h.GWPrivateKey, &h.GWPublicKey, &h.TunnelIPv4,
		&h.TunnelIPv6, &h.ConsumerWGPublicKey, &h.ConsumerTunnelIPv4,
		&h.ConsumerTunnelIPv6, &h.Endpoint, &h.Transport, &h.ListenPort,
		&h.Params, &h.Keepalive, &h.State)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &h, err
}

func scanHosts(rows pgx.Rows, err error) ([]Host, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Host
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *h)
	}
	return out, rows.Err()
}

func (s *Store) CreateHost(ctx context.Context, h *Host) error {
	if len(h.Params) == 0 {
		h.Params = []byte("{}") // params jsonb NOT NULL default
	}
	err := s.Pool.QueryRow(ctx,
		`INSERT INTO hosts (name, node, owner_id, consumer_id, wg_public_key, wg_preshared_key,
		   gw_private_key, gw_public_key, tunnel_ipv4, tunnel_ipv6,
		   consumer_wg_public_key, consumer_tunnel_ipv4, consumer_tunnel_ipv6,
		   endpoint, transport, listen_port, params, keepalive, state)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,'active')
		 RETURNING id`,
		h.Name, h.Node, h.OwnerID, h.ConsumerID, h.WGPublicKey, h.WGPreSharedKey,
		h.GWPrivateKey, h.GWPublicKey, h.TunnelIPv4, h.TunnelIPv6,
		h.ConsumerWGPublicKey, h.ConsumerTunnelIPv4, h.ConsumerTunnelIPv6,
		h.Endpoint, h.Transport, h.ListenPort, h.Params, h.Keepalive).
		Scan(&h.ID)
	// The insert hard-codes the initial state; RETURNING only fills ID,
	// so mirror it into the struct the caller serializes back to the API.
	h.State = "active"
	return err
}

func (s *Store) SetHostConsumerKey(ctx context.Context, id uuid.UUID, pubKey string) error {
	_, err := s.Pool.Exec(ctx,
		`UPDATE hosts SET consumer_wg_public_key=$2, updated_at=now() WHERE id=$1`, id, pubKey)
	return err
}

func (s *Store) UpdateHostState(ctx context.Context, id uuid.UUID, state string) error {
	_, err := s.Pool.Exec(ctx, `UPDATE hosts SET state=$2, updated_at=now() WHERE id=$1`, id, state)
	return err
}

func (s *Store) UpdateHostConsumer(ctx context.Context, id uuid.UUID, consumer uuid.UUID) error {
	_, err := s.Pool.Exec(ctx, `UPDATE hosts SET consumer_id=$2, updated_at=now() WHERE id=$1 AND owner_id<>$2`, id, consumer)
	return err
}

func (s *Store) DeleteHost(ctx context.Context, id uuid.UUID) error {
	ct, err := s.Pool.Exec(ctx, `DELETE FROM hosts WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) ForwardsByHost(ctx context.Context, hostID uuid.UUID) ([]Forward, error) {
	rows, err := s.Pool.Query(ctx,
		`SELECT id, host_id, public_port, target_port, proto, label
		 FROM forwards WHERE host_id=$1 ORDER BY public_port`, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Forward
	for rows.Next() {
		var f Forward
		if err := rows.Scan(&f.ID, &f.HostID, &f.PublicPort, &f.TargetPort, &f.Proto, &f.Label); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func (s *Store) Forwards(ctx context.Context) ([]Forward, error) {
	rows, err := s.Pool.Query(ctx,
		`SELECT id, host_id, public_port, target_port, proto, label FROM forwards ORDER BY host_id, public_port`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Forward
	for rows.Next() {
		var f Forward
		if err := rows.Scan(&f.ID, &f.HostID, &f.PublicPort, &f.TargetPort, &f.Proto, &f.Label); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func (s *Store) CreateForward(ctx context.Context, f *Forward) error {
	return s.Pool.QueryRow(ctx,
		`INSERT INTO forwards (host_id, public_port, target_port, proto, label)
		 VALUES ($1,$2,$3,$4,$5) RETURNING id`,
		f.HostID, f.PublicPort, f.TargetPort, f.Proto, f.Label).Scan(&f.ID)
}

func (s *Store) DeleteForward(ctx context.Context, id uuid.UUID) error {
	ct, err := s.Pool.Exec(ctx, `DELETE FROM forwards WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) Event(ctx context.Context, userID uuid.UUID, authMethod, action, objType, objID string, detail []byte) error {
	_, err := s.Pool.Exec(ctx,
		`INSERT INTO events (user_id, auth_method, action, object_type, object_id, detail)
		 VALUES ($1,$2,$3,$4,$5,$6)`,
		&userID, authMethod, action, objType, objID, detail)
	return err
}

// UsedTunnelIPs / UsedPorts let the allocator avoid taken values.
func (s *Store) UsedTunnelIPs(ctx context.Context) (map[string]bool, map[string]bool, error) {
	rows, err := s.Pool.Query(ctx,
		// host() strips the netmask: inet::text keeps "/32" and would
		// never match the bare IPs the allocator compares against.
		`SELECT host(tunnel_ipv4)::text, host(tunnel_ipv6)::text,
		        host(consumer_tunnel_ipv4)::text, host(consumer_tunnel_ipv6)::text
		 FROM hosts`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	v4, v6 := map[string]bool{}, map[string]bool{}
	for rows.Next() {
		var a, b string
		var c, d *string
		if err := rows.Scan(&a, &b, &c, &d); err != nil {
			return nil, nil, err
		}
		v4[a], v6[b] = true, true
		if c != nil {
			v4[*c] = true
		}
		if d != nil {
			v6[*d] = true
		}
	}
	return v4, v6, rows.Err()
}

// Token is a personal access token row. SecretHash never leaves the store:
// the wire type in api/ exposes metadata only, and the plaintext secret
// exists exactly once, in the create response.
type Token struct {
	ID         uuid.UUID  `json:"id"`
	Label      string     `json:"label"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

func (s *Store) CreateToken(ctx context.Context, userID uuid.UUID, label string, hash []byte) (*Token, error) {
	t := &Token{Label: label}
	err := s.Pool.QueryRow(ctx,
		`INSERT INTO tokens (user_id, secret_hash, label) VALUES ($1,$2,$3)
		 RETURNING id, created_at`, userID, hash, label).Scan(&t.ID, &t.CreatedAt)
	if err != nil {
		return nil, err
	}
	return t, nil
}

func (s *Store) TokensByUser(ctx context.Context, userID uuid.UUID) ([]Token, error) {
	rows, err := s.Pool.Query(ctx,
		`SELECT id, label, created_at, last_used_at, revoked_at
		 FROM tokens WHERE user_id=$1 ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Token{}
	for rows.Next() {
		var t Token
		if err := rows.Scan(&t.ID, &t.Label, &t.CreatedAt, &t.LastUsedAt, &t.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// RevokeToken marks a token dead instead of deleting it: the audit trail
// keeps the revocation time, and a leaked token is revoke-not-rotate.
func (s *Store) RevokeToken(ctx context.Context, userID, id uuid.UUID) error {
	ct, err := s.Pool.Exec(ctx,
		`UPDATE tokens SET revoked_at=now() WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL`,
		id, userID)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// TouchToken records usage for the token that actually authenticated, not
// every token the user owns (the previous user-level UPDATE poisoned the
// last_used_at of untouched tokens).
func (s *Store) TouchToken(ctx context.Context, id uuid.UUID) {
	_, _ = s.Pool.Exec(ctx, `UPDATE tokens SET last_used_at=now() WHERE id=$1`, id)
}

// Users lists users for panel invitations. Admins see everyone; a regular
// caller gets the same list (names and ids are already public to any
// authenticated user who can invite a consumer by name).
func (s *Store) Users(ctx context.Context, q string) ([]User, error) {
	rows, err := s.Pool.Query(ctx,
		`SELECT id, authentik_sub, display_name, is_admin FROM users
		 WHERE $1 = '' OR display_name ILIKE '%'||$1||'%'
		 ORDER BY display_name LIMIT 100`, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []User{}
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.AuthentikSub, &u.DisplayName, &u.IsAdmin); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// Event is one audit row as exposed over the API.
type Event struct {
	ID         int64           `json:"id"`
	At         time.Time       `json:"at"`
	UserID     *uuid.UUID      `json:"user_id,omitempty"`
	AuthMethod string          `json:"auth_method"`
	Action     string          `json:"action"`
	ObjectType string          `json:"object_type"`
	ObjectID   string          `json:"object_id"`
	Detail     json.RawMessage `json:"detail"`
}

// Events returns the newest audit rows. An empty userID means "everyone"
// (admin view); otherwise the caller sees only their own actions.
func (s *Store) Events(ctx context.Context, userID *uuid.UUID, limit int) ([]Event, error) {
	rows, err := s.Pool.Query(ctx,
		`SELECT id, at, user_id, auth_method, action, object_type, object_id, detail
		 FROM events WHERE $1::uuid IS NULL OR user_id = $1
		 ORDER BY id DESC LIMIT $2`, userID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Event{}
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ID, &e.At, &e.UserID, &e.AuthMethod, &e.Action,
			&e.ObjectType, &e.ObjectID, &e.Detail); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// UpdateHostFields applies the PATCH surface: endpoint, keepalive and the
// invited consumer are the only mutable knobs after creation. Keys keep
// their own endpoints so BYOK stays one-way.
func (s *Store) UpdateHostFields(ctx context.Context, id uuid.UUID, endpoint *string, keepalive *int, consumer *uuid.UUID) error {
	ct, err := s.Pool.Exec(ctx,
		`UPDATE hosts SET
		   endpoint    = COALESCE($2, endpoint),
		   keepalive   = COALESCE($3, keepalive),
		   consumer_id = COALESCE($4, consumer_id),
		   updated_at  = now()
		 WHERE id=$1`, id, endpoint, keepalive, consumer)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) UsedPorts(ctx context.Context) (map[int]bool, error) {
	rows, err := s.Pool.Query(ctx, `SELECT listen_port FROM hosts WHERE state='active' OR state='suspended'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := map[int]bool{}
	for rows.Next() {
		var p int
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		m[p] = true
	}
	return m, rows.Err()
}
