package store

import (
	"context"
	"errors"

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
	ID           uuid.UUID
	AuthentikSub string
	DisplayName  string
	IsAdmin      bool
}

type Host struct {
	ID             uuid.UUID
	Name           string
	OwnerID        uuid.UUID
	ConsumerID     uuid.UUID
	WGPublicKey    string
	WGPreSharedKey string
	GWPrivateKey   string
	GWPublicKey    string
	TunnelIPv4     string
	TunnelIPv6     string
	ConsumerWGPublicKey *string
	ConsumerTunnelIPv4  *string
	ConsumerTunnelIPv6  *string
	Endpoint       *string
	Transport      string
	ListenPort     int
	Params          []byte
	Keepalive       int
	State           string
}

type Forward struct {
	ID         uuid.UUID
	HostID     uuid.UUID
	PublicPort int
	TargetPort int
	Proto      string
	Label      string
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

func (s *Store) HostsByUser(ctx context.Context, uid uuid.UUID) ([]Host, error) {
	return scanHosts(s.Pool.Query(ctx, hostCols+` WHERE owner_id=$1 OR consumer_id=$1 ORDER BY created_at`, uid))
}

const hostCols = `SELECT id, name, owner_id, consumer_id, wg_public_key, wg_preshared_key,
	gw_private_key, gw_public_key, tunnel_ipv4::text, tunnel_ipv6::text,
	consumer_wg_public_key, consumer_tunnel_ipv4::text, consumer_tunnel_ipv6::text,
	endpoint, transport, listen_port, params, keepalive, state FROM hosts`

func scanHost(r pgx.Row) (*Host, error) {
	var h Host
	err := r.Scan(&h.ID, &h.Name, &h.OwnerID, &h.ConsumerID, &h.WGPublicKey,
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
	return s.Pool.QueryRow(ctx,
		`INSERT INTO hosts (name, owner_id, consumer_id, wg_public_key, wg_preshared_key,
		   gw_private_key, gw_public_key, tunnel_ipv4, tunnel_ipv6,
		   consumer_wg_public_key, consumer_tunnel_ipv4, consumer_tunnel_ipv6,
		   endpoint, transport, listen_port, params, keepalive, state)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,'active')
		 RETURNING id`,
		h.Name, h.OwnerID, h.ConsumerID, h.WGPublicKey, h.WGPreSharedKey,
		h.GWPrivateKey, h.GWPublicKey, h.TunnelIPv4, h.TunnelIPv6,
		h.ConsumerWGPublicKey, h.ConsumerTunnelIPv4, h.ConsumerTunnelIPv6,
		h.Endpoint, h.Transport, h.ListenPort, h.Params, h.Keepalive).Scan(&h.ID)
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
		`SELECT tunnel_ipv4::text, tunnel_ipv6::text,
		        consumer_tunnel_ipv4::text, consumer_tunnel_ipv6::text
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