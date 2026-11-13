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
stack, or a web framework: Postgres is the existing `postgresql@17-main`
cluster on **glacier** (Infra AGENTS.md §15), identity is Authentik
(also glacier), DNS is the existing Cloudflare zone, TLS is the
existing **nginx** (AGENTS.md §11) — no new reverse proxy.

Core language is **Go**, CLI is Go (cobra), panel is React+Vite+TS.
Rationale in §12.

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
| authentik_sub | text not null unique | OIDC `sub` claim; null for the break-glass admin |
| display_name | text not null | from Authentik profile |
| is_admin | bool not null default false | synced from the Authentik admin group on every login/token check |
| created_at | timestamptz not null default now() | |

Users are **provisioned lazily**: first successful token validation
inserts a row.

**Admins**: two sources, unioned.
1. **Authentik group membership** (config: `authentik_admin_group`):
   on every successful OIDC/PAT auth the core re-checks group
   membership via the Authentik token introspection / userinfo and
   syncs `is_admin` — removal from the group revokes admin on the
   next request.
2. **Break-glass admin** (works when Authentik is down): a single
   login + argon2id hash in the core env file
   (`DYATEL_FALLBACK_ADMIN_USER` / `..._HASH`), validated by the
   core itself, bypassing OIDC entirely. The panel offers both
   login methods. No DB row is needed; audit events mark auth
   method (`oidc` vs `fallback`).

Admin powers (moderation): list **all** hosts/forwards/users,
suspend/unsuspend any host, delete any object, read the full event
log. Admins act on top of §4, they do not replace owner/consumer
trust — they police it.

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
| wg_public_key | text not null | peer key — **supplied by the owner (BYOK), never core-generated** |
| wg_preshared_key | text not null | generated at insert (core; shared secret of the pair) |
| gw_private_key | text not null | berg-side keypair for this host, core-generated |
| gw_public_key | text not null | handed to the host |
| tunnel_ipv4 | inet not null unique | `10.13.36.x/32` |
| tunnel_ipv6 | inet not null unique | `fd00:36::x/128` |
| endpoint | text | `host:port` the host dials in from (may be dynamic, i.e. null) |
| transport | text not null default 'wireguard' | `wireguard \| amneziawg \| xray-vless` (§3.4a) |
| listen_port | int not null unique | berg-side port, allocated by core per host |
| params | jsonb not null default '{}' | transport-specific knobs |
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

### 3.4a transports (multi-tunnel support)

Dyatel is transport-pluggable. Each **host** picks exactly one
transport and gets a **dedicated listen port on berg**, allocated
from a core-managed pool (like tunnel IPs):

| transport | listen port pool | applier on berg | notes |
|---|---|---|---|
| `wireguard` | 51820–51899/udp | `wg syncconf` | default, phase 1 |
| `amneziawg` | 51900–51999/udp | `awg syncconf` | phase 1b; same schema, AWG obfuscation fields in `hosts.params jsonb` |
| `xray-vless` | 5200–5299/tcp | xray API/grpc | phase 2; host row carries UUID+TLS params; forward = routing rule |

Masquerade modes (`params.mode`, copied from the Infra Glacier/Floe pattern;
`tls` is the default):

- **`tls`** — xray owns the public pool port with real TLS (BYOK cert files
  or `{{DYATEL_CERT_PEM}}`/`{{DYATEL_KEY_PEM}}` placeholders); optional
  `fallback` (`host:port`) routes non-VLESS probes to a real local site
  (Floe). Inbounds get `sniffing.destOverride ["http","tls","quic"]`.
- **`nginx`** — xray listens on `127.0.0.1` only, transport VLESS over
  WebSocket with `security "none"` and a masquerade `ws_path` inside the
  real vhost URL space; TLS is terminated by the operator's nginx, which
  `proxy_pass`es the ws path to the loopback port (Glacier). `public_port`
  (default 443) is the vhost TLS port the consumer dials; cert_file/key_file
  are rejected in this mode.

REALITY is rejected at params-parse time everywhere (unusable in RU); WARP
egress, mail-port blocks and DoH DNS from the source pattern are
deliberately not ported.

Schema impact: `hosts` gains `transport text not null default 'wireguard'`,
`listen_port int not null unique` (allocated by core, freed on delete),
and `params jsonb not null default '{}'` for transport-specific knobs.
Each transport is a Go interface in core:

```go
type Transport interface {
    RenderProxerConfig(h Host) ([]byte, error)  // owner-side conf
    RenderClientConfig(h Host) ([]byte, error)  // consumer-side conf
    ApplyDesired(hosts []Host) error            // berg-side apply
    Drift(hosts []Host) ([]Diff, error)          // parse live state
}
```

Phasing: WG ships in phase 1, AWG right after (it is a wg fork —
renderer differs, model identical), Xray is a later phase.

### 3.4b key custody (BYOK)

**The core never generates or sees a user-side private key.**
The owner (`проксер`) and the consumer (`клиент`) each generate
their own keypair locally (`dyatelctl genkeys`, or
`wg genkey` / `awg genkey` / xray `x25519` by hand) and submit
only public keys. What the core does generate and store:
- the **PSK** (it is a shared secret of the pair anyway);
- the **berg-side keypair** (`gw_*` columns) — the core operates
  berg's tunnel interface, so its private key is the core's own,
  not a user secret.
Config rendering works on **public material only**: the core's
`GET .../config` returns a template with a `{{private_key}}`
placeholder; `dyatelctl` (or the Ansible role) fills it from the
locally generated key. A hand-rolled setup does the same with
`wg genkey`. The core could not leak a user private key because
it never had one.

### 3.4c bring-up paths (manual or Ansible, per side)

Both roles (проксер and клиент) can bring up their side either
way; identical rendered configs, identical transports:

| side | manual | Ansible role (`ansible/roles/…`) |
|---|---|---|
| proxer (owner) | `dyatelctl genkeys` → `POST /hosts` → `dyatelctl config proxer` → `wg-quick up` / `awg-quick up` / `xray -c` | `dyatel_proxer` |
| client (consumer) | `dyatelctl genkeys` → `dyatelctl config client` → same commands | `dyatel_client` |

| transport | package | config artifact | systemd unit |
|---|---|---|---|
| `wireguard` | `wireguard-tools` | `/etc/wireguard/dyatel.conf` | `wg-quick@dyatel` |
| `amneziawg` | `amneziawg-tools` | `/etc/amnezia/amneziawg/dyatel.conf` (AWG params from `hosts.params`) | `awg-quick@dyatel` |
| `xray-vless` | `xray` | `/etc/xray/dyatel.json` (UUID+TLS, masquerade mode) | `xray@dyatel` |

The roles are **thin deployers**: install the package, fetch the
rendered config (via `dyatelctl` with a PAT, or a template var
containing the rendered config), drop it at the path above, enable
the unit. Zero provisioning logic — rendering is always the
core's job; roles only deploy. This keeps the same matrix for
all three transports and both sides.

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

| action | owner | consumer | other | admin |
|---|---|---|---|---|
| create/delete/edit host (keys, consumer, endpoint) | ✔ | — | — | ✔ |
| create/delete forward on the host | — | ✔ | — | ✔ |
| create/delete DNS record on a forward | — | ✔ | — | ✔ |
| download host wg config | ✔ | ✔ | — | ✔ |
| download consumer wg config | ✔ | ✔ | — | ✔ |
| suspend host | ✔ | — | — | ✔ |
| list all users / hosts / events | — | — | — | ✔ |

Rationale: the owner trusts *one* consumer with the tunnel; the
consumer decides what of the owner's services is worth publishing.
Both can fetch the WireGuard configs (they need them to bring up
either side). Admins are moderators: global visibility + override,
never needed for the happy path. Nobody else sees anything.

**How roles are acquired** (no self-service consumership):
- **owner** — self-service: `POST /hosts` with a WG public key
  (generated locally, §3.4b). You own what you created.
- **consumer** — invitation only: the owner names another Authentik
  user as consumer at host creation (or later via `PATCH`). The
  named user becomes consumer of *that host*, nothing more.
  `owner_id <> consumer_id` is enforced.
- **admin** — Authentik group or break-glass creds (§3.1).
- A user can be owner of their hosts and consumer of others' at
  the same time. Roles are per-host relations, not profile flags.

## 4a. Host provisioning flow (what "allocate port + IPs + config" means)

`POST /hosts` (owner action) triggers, in one transaction:

1. **Keys** (§3.4b BYOK): the owner submits their **public** key
   (generated locally); the core generates the PSK and the
   berg-side keypair. No user private key ever reaches the core.
2. **Allocation from core-owned pools** (config bounds, tracked in
   the `hosts` table, freed on delete):
   - `listen_port` — one UDP port on berg per host (per-host
     ports), e.g. 51820–51899;
   - `tunnel_ipv4` / `tunnel_ipv6` — one /32 and one /128 from the
     tunnel subnets.
3. **Render** both side configs (proxer + client, §3.4a) — public
   material only, private-key placeholder included.
4. Desired state is committed; the **reconcile loop** applies it
   within one tick: adds the `[Peer]` to berg's `wg-dyatel.conf`
   (`wg syncconf` — no bounce), opens `listen_port` in UFW with a
   `Dyatel host=<name>` comment.

The owner's remaining work: §3.4c — manual
(`genkeys` → `config proxer` → `wg-quick up`) or the
`dyatel_proxer` Ansible role. Either way no user private key
touches the core, and no transport logic lives outside it.

## 5. API (REST, JSON, versioned under `/api/v1`)

Served by `dyatel-core` on berg bound to `127.0.0.1:8100`
(Infra port policy: application services > 8000 on loopback; IPv6
`...::8001`-style alias assigned at deploy). TLS terminated by the
existing **nginx** (Infra AGENTS.md §11) vhost
`api.dyatel.test.nada.mu` (staging). **Do not rely on the apex
wildcard `*.nada.mu`** — live check 2026-11-13: it resolves A to
glacier (195.58.153.219), not berg, and has no AAAA. The vhost
name gets an explicit DNS record at deploy time, inside the
AGENTS.md §10 whitelist. Auth via PAT bearer, OIDC bearer
(panel), or the break-glass admin login (§3.1).
403 semantics: owner/consumer checks as §4.

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
Endpoint      = berg.example:{listen_port}
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
  Each host listens on its **own** `listen_port` (§3.4a) — per-host
  ports, no shared 51820.
- **UFW ports**: each host's `listen_port` and each forward's
  `public_port` get `ufw allow proto {tcp,udp} to any port {port}`
  with comment `Dyatel host={name}` — reconcile deletes rules whose
  comment host is absent from Postgres (reuses the v1.0.1 lesson:
  parse `ufw status`, never blind-add).
- **UFW routes**: `route allow to {tunnel_ip} port {target_port}
  proto {proto}` with comment `Dyatel host={name} fwd={id}` — same
  comment-driven reconciliation, so stale IPs are impossible by
  construction.
- **Proxer-side UFW contract** (outside core ownership, verified in the
  awg-smoke staging run): the proxer/consumer host's *own* firewall must
  allow the gw transport replies explicitly — `allow in proto udp from
  {gw_public_ip} port {listen_port}` plus the LAN-path variant
  (`from {gw_lan_cidr} port {listen_port}`) when host and gw share a
  LAN. The gw's UDP replies source from its LAN address (route-selected),
  not the public IP the client dials, so conntrack never matches the
  reverse tuple and plain UFW default-drops them as unsolicited.
  Same shape as the v1.0.1 gw transport rules (§3.4c). The rendered
  client `Endpoint` is the configured public host (`PublicEndpointHost`),
  which must resolve to a reachable A record for dial-in clients —
  the awg-smoke run showed AAAA-first resolution sending handshakes
  into a dead v6 path (fix: IPv4 endpoint for smoke).
- **POSTROUTING MASQ**: forwarded packets keep the client's internet
  source IP after DNAT, which the host's wg cryptokey routing
  (AllowedIPs = gw /32 only) silently drops. Core adds a per-iface
  `-po` chain (`DYATEL-<ifname>-po`) hung off POSTROUTING with
  `MASQUERADE -o <ifname> -d {tunnel_ip}/32`; the return path un-NATs
  via conntrack. Matching on the post-DNAT destination is the only
  correct form here: `--ctorigdst` still carries the pre-DNAT public
  IP in POSTROUTING (never matches), and `--ctstatus DNAT` is rejected
  by iptables-nft 1.8.9 ("Bad ctstatus").
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
  `dyatel` lives in the existing `postgresql@17-main` cluster on
  **glacier**, reached by core (on berg) over the wireguard mesh —
  separate role, no cross-grants to other DBs.
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
| packages (wireguard-tools, amneziawg-tools, postgres client) | Ansible |
| sysctl forwarding drop-in | Ansible |
| `/etc/wireguard` dir + `wg-quick@wg-dyatel` unit enable | Ansible |
| core binary install, `dyatel-core.service`, env file | Ansible |
| `dyatel` db + role on glacier `17-main` (one-shot) | Ansible |
| nginx vhost `api.<base_domain>` → `127.0.0.1:8100`, cert | Ansible |
| peers, transports, UFW ports/routes, NAT, DNS | **core** (hands off) |

Postgres provisioning runs against **glacier** (where `17-main`
lives); the rest of the role targets berg. Vault placeholders
(`vault_dyatel_db_password`, `vault_dyatel_cloudflare_token`) are
added by agent with `CHANGE_ME` values — the user fills real values
via `ansible-vault edit` (Infra §6: agent never touches secrets).

Infra repo conventions stay: symmetric uninstall, idempotent re-runs,
`[firewall]`/`[uninstall]` tags. A `sleep`-based smoke test validates
that core answered `/status` after deploy.

## 10. Deliverables and phasing

| phase | deliverable | done when |
|---|---|---|
| 0 (this doc) | RFC merged | user says ok |
| 1 core (wg) | `cmd/dyatel-core`, migrations, reconcile, `/api/v1`, WG transport | **done**: node `berg` reconciles host `gsix-tunnel`; consumer LXC `gsix` handshakes and pings `10.13.36.1` + `fd00:36::1` end-to-end |
| 1b core (awg) | AWG transport plugin | same, via AWG client |
| 2 CLI | `dyatelctl login/expose/status`, PAT auth | full cycle from terminal, zero curl |
| 3 web | React+Vite+TS panel (shadcn/ui, tanstack-query) + Authentik OIDC | the "panel" the user asked for originally |
| later | `xray-vless` transport | host connects via VLESS |

Deployment topology: **one binary, two core daemons, one shared
Postgres**. Staging/production split is by node column, not by host:
`test` Incus VM on berg runs node `test` (API 127.0.0.1:8100, db over the
local socket), berg itself runs node `berg` (API 127.0.0.1:8100, db over
incusbr0 to the test VM, scram-sha-256). Port/IP allocators are global
(wg 51820–51899/udp, awg 51900–51999/udp, xray 5200–5299/tcp; tunnel nets
`10.13.36.0/24` + `fd00:36::/64`, core `.1`, gw `.2`, consumer `.3`).
`DYATEL_NODE` selects which hosts a node reconciles; `/status` reports
per-node state. The existing `dyatel` DB on test is reused ("we do not
own Postgres"). The legacy `dyatel_gateway` on test is decommissioned
(frozen v1.0.1). Testbed-first and idempotency (`changed=0`) rules apply
throughout.

Phase 1 alone already satisfies "usable without UI" (§2.5).

## 11. Open questions

1. ~~Public berg port per host~~ — **resolved: per-host ports** (§3.4a).
2. ~~IPv6 endpoint dials~~ — moot: endpoint is a DNS name resolving
   to both A and AAAA.
3. ~~DNS zone for forward records~~ — **resolved**: staging stays on
   `dyatel.test.nada.mu`. Production zone decision (dedicated
   `dyatel.nada.mu` wildcard vs §10 whitelist extension) is the
   user's call at the release gate; no production deployment
   without explicit user approval. Note the existing apex wildcard
   resolves to glacier, not berg — do not rely on it.
4. ~~Base domain for the core API vhost~~ — **resolved**: staging
   `api.dyatel.test.nada.mu`; production `api.dyatel.nada.mu` on
   berg (existing nginx+ACME → `127.0.0.1:8100`), deployed only at
   the user-approved release gate.

## 12. Stack decision

| layer | choice | why |
|---|---|---|
| core | **Go** (chi, pgx v5, golang-migrate, cloudflare-go, x/crypto argon2) | single static binary, first-class `wg`/exec ecosystem, fastest path to a correct reconcile loop; Rust rejected: lower iteration speed for a CRUD+loop daemon |
| CLI | **Go** (cobra, carapace, OpenAPI-generated client) | shares types with core, single binary for user's servers |
| web | **React + Vite + TypeScript** (shadcn/ui, tanstack-query, oidc-client-ts) | static dist served by existing nginx, stateless, auth fully outsourced to Authentik |

Go vs Rust was raised: for a control plane that is 90% DB + REST +
`wg syncconf` calls, Go's development speed and pgx/chi maturity
outweigh Rust's runtime-safety edge; the daemon is memory-safe
enough behind nginx, UFW, and a Postgres role.