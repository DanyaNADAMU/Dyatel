CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE users (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    authentik_sub text NOT NULL UNIQUE,
    display_name  text NOT NULL,
    is_admin      boolean NOT NULL DEFAULT false,
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE tokens (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    secret_hash bytea NOT NULL UNIQUE,
    label       text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz,
    revoked_at  timestamptz
);

CREATE TABLE hosts (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name              text NOT NULL UNIQUE,
    owner_id          uuid NOT NULL REFERENCES users(id),
    consumer_id       uuid NOT NULL REFERENCES users(id),
    wg_public_key     text NOT NULL,
    wg_preshared_key  text NOT NULL,
    gw_private_key    text NOT NULL,
    gw_public_key     text NOT NULL,
    tunnel_ipv4       inet NOT NULL UNIQUE,
    tunnel_ipv6       inet NOT NULL UNIQUE,
    -- consumer side (BYOK key registered by consumer; IPs allocated at insert)
    consumer_wg_public_key text,
    consumer_tunnel_ipv4   inet UNIQUE,
    consumer_tunnel_ipv6   inet UNIQUE,
    endpoint          text,
    transport         text NOT NULL DEFAULT 'wireguard'
                      CHECK (transport IN ('wireguard','amneziawg','xray-vless')),
    listen_port       int  NOT NULL UNIQUE,
    params            jsonb NOT NULL DEFAULT '{}',
    keepalive         int  NOT NULL DEFAULT 25,
    state             text NOT NULL DEFAULT 'active' CHECK (state IN ('active','suspended')),
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT no_self_trust CHECK (owner_id <> consumer_id)
);

CREATE INDEX hosts_owner_idx ON hosts(owner_id);
CREATE INDEX hosts_consumer_idx ON hosts(consumer_id);

CREATE TABLE forwards (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id     uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    public_port int  NOT NULL CHECK (public_port BETWEEN 1 AND 65535),
    target_port int  NOT NULL CHECK (target_port BETWEEN 1 AND 65535),
    proto       text NOT NULL CHECK (proto IN ('tcp','udp')),
    label        text NOT NULL DEFAULT '',
    created_at   timestamptz NOT NULL DEFAULT now(),
    UNIQUE (host_id, public_port, proto)
);

CREATE TABLE dns_records (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    forward_id    uuid NOT NULL UNIQUE REFERENCES forwards(id) ON DELETE CASCADE,
    name          text NOT NULL UNIQUE,
    cloudflare_id text,
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE events (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    at          timestamptz NOT NULL DEFAULT now(),
    user_id     uuid REFERENCES users(id),
    auth_method text NOT NULL DEFAULT 'oidc' CHECK (auth_method IN ('oidc','pat','fallback')),
    action      text NOT NULL,
    object_type text NOT NULL,
    object_id   text NOT NULL,
    detail      jsonb NOT NULL DEFAULT '{}'
);

CREATE INDEX events_object_idx ON events(object_type, object_id);

-- NAT mark + marked port range (reconcile uses it on berg)
CREATE TABLE meta (
    key   text PRIMARY KEY,
    value text NOT NULL
);