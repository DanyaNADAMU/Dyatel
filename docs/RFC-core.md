# RFC: Dyatel Core — declarative L4 game proxy control plane

- Status: **draft** (phase 0)
- Target release: v2.0.0
- Authors: Danya, agent
- Supersedes: none (adds a control plane on top of the v1 Ansible-only deploy)

## 1. Summary

Dyatel today is a single-purpose Ansible deploy: one gateway (berg),
one WireGuard client (the user's home server), one forwarded game port.
Every change is a manual `ansible-playbook` run with extra-vars.

This RFC defines **dyatel-core**: a small Go control plane that owns the
tunnel topology declaratively. Desired state lives in Postgres
(database `dyatel`); a **reconcile loop** renders and applies
`wg` peers, UFW rules, and Cloudflare DNS records. Human interfaces
(CLI `dyatelctl`, later a web panel) are thin clients over the core API.
The v1 Ansible roles are frozen at v1.0.1 and shrink to bootstrap-only.

Nothing in this RFC introduces a new database server, an authentication
stack, or a web framework: Postgres is the existing instance, identity
is Authentik, DNS is the existing Cloudflare zone.

## 2. Requirements

1. A registered user (Authentik) can register their server as a
   **host** (WireGuard peer behind berg).
2. A host has exactly one **owner** and exactly one **consumer**
   (a different user the owner trusts). No fan-out.
3. The **consumer** chooses which ports of the host to forward through
   berg and names them (`mc1.dyatel.example`).
4. DNS records are plain `A`/`AAAA` entries in the Cloudflare zone
   pointing at berg; the name is cosmetic, the proxy is L4.
5. The system is fully usable **without any UI**: core API + CLI.
6. Core applies state itself (`wg set`, `ufw`) — no Ansible in the
   data path. Ansible remains for server skeleton only (§9).
7. No backward compatibility with the v1 manual deploy: first
   reconcile **replaces** the hand-rolled `wg-dyatel.conf` and UFW
   rules (§8).
8. Reconcile is idempotent: drift (manual edits, reboot, lost rules)
   self-heals within one loop tick.

## 3. Data model

Postgres database `dyatel` on the existing instance. Migrations via
golang-migrate, files in `migrations/`.

### 3.1 users

| column | type | notes |
|---|---|---|
| id | uuid pk default gen_random_uuid() | |
| authentik_sub | text not null unique | OIDC `sub` claim |
| display_name | text not null | from Authentik profile |
| created_at | timestamptz not null default now() | |

Users are **provisioned lazily**: first successful token validation
inserts a row. No admin user management.

### 3.2 tokens (PAT)

| column | type | notes |
|---|---|---|
| id | uuid pk | |
| user_id | uuid not null references users | |
| secret_hash | bytea not null unique | argon2id(token) |
| label | text not null | shown in CLI as `laptop`, `vps` |
| created_at / last_used_at / revoked_at | timestamptz | |

Token format: `dyatel_<32 bytes base64url>`; only the hash is stored.
CLI sends `Authorization: Bearer dyatel_…`.

### 3.3 hosts

| column | type | notes |
|---|---|---|
| id | uuid pk | |
| name | text not null unique | `[a-z0-9-]{2,32}`, used in DNS labels |
| owner_id | uuid not null references users | who runs the server |
| consumer_id | uuid not null references users, ≠ owner_id | who consumes the tunnel |
| wg_public_key | text not null | peer key |
| wg_preshared_key | text not null | generated at insert |
| gw_private_key | text not null | berg-side keypair for this host |
| gw_public_key | text not null | handed to the host |
| tunnel_ipv4 | inet not null unique | `10.13.36.x/32` |
| tunnel_ipv6 | inet not null unique | `fd00:36::x/128` |
| endpoint | text | `host:port` the host dials in from (may be dynamic, i.e. null) |
| keepalive | int not null default 25 | |
| state | text not null default 'active' | `active \| suspended` |
| created_at / updated_at | timestamptz | |

Tunnel IPs are allocated from a free list in
`10.13.36.0/24` / `fd00:36::/64` (first-fit, `.2`–`.250`; `.1` is berg).
Constraint `owner_id <> consumer_id` enforces the trust pair.

### 3.4 forwards

| column | type | notes |
|---|---|---|
| id | uuid pk | |
| host_id | uuid not null references hosts | |
| public_port | int not null check (1–65535) | port on berg |
| target_port | int not null | port on the host |
| proto | text not null check (proto in ('tcp','udp')) | |
| label | text not null | e.g. `minecraft` |
| created_at | timestamptz | |

Unique `(host_id, public_port, proto)`. **Created by the consumer.**
The consumer may only reference their own consumed host.

### 3.5 dns_records

| column | type | notes |
|---|---|---|
| id | uuid pk | |
| forward_id | uuid not null references forwards | one per forward |
| name | text not null unique | `mc1.dyatel.example` (zone fixed in config) |
| cloudflare_id | text | CF record id once created |
| created_at | timestamptz | |

One record per forward, `A` berg_ipv4 + `AAAA` berg_ipv6 via CF API.
Renaming = delete + create (core handles the CF call).

### 3.6 events (audit log)

Append-only `{id, at, user_id, action, object_type, object_id, detail jsonb}`.
Written by core on every mutation. Powers `dyatelctl status` history
and, later, the panel activity feed.

## 4. Ownership and permission matrix

| action | owner | consumer | other |
|---|---|---|---|
| create/delete/edit host (keys, consumer, endpoint) | ✔ | — | — |
| create/delete forward on the host | — | ✔ | — |
| create/delete DNS record on a forward | — | ✔ | — |
| download host wg config | ✔ | ✔ | — |
| download consumer wg config | ✔ | ✔ | — |
| suspend host | ✔ | — | — |

Rationale: the owner trusts *one* consumer with the tunnel; the
consumer decides what of the owner's services is worth publishing.
Both can fetch the WireGuard configs (they need them to bring up
either side). Nobody else sees anything.

## 5. API (REST, JSON, versioned under `/api/v1`)

Served by `dyatel-core` on berg, TLS terminated by an existing reverse
proxy (Caddy/Nginx — decided at deploy time), auth via PAT bearer or
OIDC bearer (panel). 403 semantics: owner/consumer checks as §4.

```
POST   /api/v1/users/me                # idempotent provision on first auth
GET    /api/v1/users/me
POST   /api/v1/tokens                  # {label} -> full token shown ONCE
GET    /api/v1/tokens                  # list (metadata only)
DELETE /api/v1/tokens/{id}             # revoke

GET    /api/v1/hosts                   # mine as owner + mine as consumer
POST   /api/v1/hosts                   # {name, wg_public_key, consumer}
PATCH  /api/v1/hosts/{id}              # endpoint, consumer, keepalive, state
DELETE /api/v1/hosts/{id}
GET    /api/v1/hosts/{id}/config        # rendered wg-quick conf (host side)

GET    /api/v1/hosts/{id}/forwards
POST   /api/v1/hosts/{id}/forwards      # consumer only
DELETE /api/v1/hosts/{id}/forwards/{fid}
POST   /api/v1/forwards/{fid}/dns      # {name} -> record + CF sync
DELETE /api/v1/forwards/{fid}/dns

POST   /api/v1/reconcile                # SIGUSR1-equivalent: trigger loop NOW
GET    /api/v1/status                   # drift report (last apply, diffs)
```

All mutations are **optimistic**: core validates, writes to Postgres,
and returns `202 {reconcile_queued}`. Actual network application
happens in the loop (§6). `GET /status` tells whether desired ==
applied.

### 4→5 bis. Rendering

Host-side wg-quick config (consumer's server dials berg):

```ini
[Interface]
Address    = {tunnel_ipv4}/32, {tunnel_ipv6}/128
PrivateKey = <consumer private key — generated by core, returned once>
DNS        = 10.13.36.1

[Peer]
PublicKey     = {gw_public_key}
PresharedKey  = {wg_preshared_key}
AllowedIPs    = 10.13.36.1/32, fd00:36::1/128
Endpoint      = berg.example:{wg_listen_port}
PersistentKeepalive = {keepalive}
```

Berg-side peers live in `wg-dyatel.conf` as `[Peer]` blocks, one per
host, rendered by core (not Ansible) from §3.3.

## 6. Reconcile loop

```
every 30s (and on POST /reconcile):
  desired  := read hosts(active) + forwards + dns from Postgres
  applied  := parse wg showconf + ufw status + CF zone records
  for diff in three-way(desired, applied):
    apply  (wg setconf / ufw route add|delete / CF upsert)
  record run in runs table {at, drift: bool, detail}
```

- **wg**: core owns `/etc/wireguard/wg-dyatel.conf` and applies with
  `wg syncconf wg-dyatel <(wg-quick strip wg-dyatel)` — no interface
  bounce, no dropped handshakes. Key files `chmod 600`, owned root.
- **UFW ports**: `ufw allow proto tcp from any to any port {public_port}`
  with comment `Dyatel host={name}` — reconcile deletes rules whose
  comment host is absent from Postgres (reuses the v1.0.1 lesson:
  parse `ufw status`, never blind-add).
- **UFW routes**: `route allow to {tunnel_ip} port {target_port}
  proto {proto}` with comment `Dyatel host={name} fwd={id}` — same
  comment-driven reconciliation, so stale IPs are impossible by
  construction.
- **before.rules NAT**: core maintains a marked block
  `# BEGIN DYATEL CORE` … `# END` with DNAT rules only; v1.0.1-style
  blockinfile content is *removed* on first run (§8).
- **DNS**: idempotent upsert by record name; orphaned CF records with
  our comment tag but no matching forward get deleted.
- **Dry-run**: `dyatelctl status` calls `GET /status` which runs the
  diff but applies nothing.

Loop tick ordering: wg → ufw → dns. A suspended host stays in wg
conf with `PersistentKeepalive` intact but its forwards' UFW routes
are removed and DNS records deleted (visible but dead is worse than
absent).

## 7. Security notes

- Core runs as root on berg (needs wg/ufw). systemd unit with
  `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`,
  `ProtectSystem=strict` + `ReadWritePaths=/etc/wireguard`,
  `NoNewPrivileges=yes`, `CapabilityBoundingSet=CAP_NET_ADMIN
  CAP_NET_RAW`.
- DB creds via systemd `EnvironmentFile=/etc/dyatel/core.env` 0600.
- Cloudflare token: scoped **Zone:DNS:Edit** on the one zone only.
- All secrets (gw private keys, PSKs) at rest in Postgres; database
  lives on the same trusted instance as the rest of Infra —
  `dyatel` database only, separate role, no cross-grants.
- PAT tokens hashed (argon2id); a leaked token is revoke-not-rotate.
- Audit events cover every mutating call (§3.6).

## 8. No backward compatibility (explicit)

The first reconcile run on berg:

1. stops and deletes the v1 `wg-quick@wg-dyatel` unit usage (the unit
   file stays — it is how core's interface comes up),
2. deletes **all** UFW rules commented `Dyatel …` (the v1.0.1 cleanup
   regexes ship as `migrations/0001`-era helper),
3. replaces `/etc/ufw/before.rules` Dyatel NAT block with the core
   block,
4. imports the current production pair (berg ↔ user's home server)
   as the first host row.

The existing tunnel goes down for exactly the duration of step 4 —
one loop tick, seconds. Accepted by owner.

## 9. What happens to Ansible

The `dyatel_gateway` role is **frozen** at v1.0.1 semantics for the
skeleton and gains new `dyatel_core` role:

| task | owner |
|---|---|
| packages (wireguard-tools, postgres client, caddy) | Ansible |
| sysctl forwarding drop-in | Ansible |
| `/etc/wireguard` dir + `wg-quick@wg-dyatel` unit enable | Ansible |
| core binary install, `dyatel-core.service`, env file | Ansible |
| Postgres `dyatel` db + role + migrations | Ansible (one-shot) |
| peers, UFW ports/routes, NAT, DNS | **core** (hands off) |

Infra repo conventions stay: symmetric uninstall, idempotent re-runs,
`[firewall]`/`[uninstall]` tags. A `sleep`-based smoke test validates
that core answered `/status` after deploy.

## 10. Deliverables and phasing

| phase | deliverable | done when |
|---|---|---|
| 0 (this doc) | RFC merged | user says ok |
| 1 core | `cmd/dyatel-core`, migrations, reconcile, `/api/v1` | staging berg: create host+forward via SQL/curl → MC client connects through berg, second run 0 drift |
| 2 CLI | `dyatelctl login/expose/status`, PAT auth | full cycle from terminal, zero curl |
| 3 web | SvelteKit panel + Authentik OIDC login | the "panel" the user asked for originally |

Phase 1 alone already satisfies "usable without UI" (§2.5).

## 11. Open questions

1. Public berg port per host: one wg listen port for everyone (51820)
   or per-host ports for nat-busting? — **Recommendation: single
   51820; hosts are clients dialing in.**
2. IPv6 endpoint dials: host config may also carry the berg IPv6 —
   agreed implicitly, cheap. — **Accepted by default.**
3. Panel domain for core API (`api.dyatel.example`?) — needed by
   phase 1 end.