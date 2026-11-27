# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [v2.4.0] - 2026-11-27

### Added
- **Cloudflare DNS sync**: `A`/`AAAA` records for forward hostnames are
  converged from `dns_records` by the reconcile loop (`DYATEL_CLOUDFLARE_TOKEN`,
  `DYATEL_DNS_ZONE`, explicit `DYATEL_PUBLIC_IPV4/_IPV6`). Mutations sync
  immediately; a drift check runs every `DYATEL_DNS_SYNC_SEC` (300s), and
  `_dns` in `/status` plus `dyatelctl status` report the last attempt.
- **DNS ownership guard**: records are tagged with a `dyatel ` comment prefix;
  foreign records are never overwritten, stale duplicates of one type are
  collapsed, and pruning only touches this node's `A`/`AAAA` records.
- **Bilingual panel**: the web UI auto-detects EN/RU from the browser, keeps
  the choice in `localStorage`, and has a header toggle; hosts, status, tokens
  and the audit feed are fully localized.
- **Panel host management**: edit hosts in place (`PATCH`), register a
  consumer BYOK public key, copy transport-specific onboarding commands for
  WG/AWG, bind DNS names to forwards, and trigger a reconcile pass.
- **CLI parity**: `dyatelctl forwards dns list|set|rm` and a human-readable
  `dyatelctl status` table (transport, handshake age, rx/tx per peer).

### Fixed
- **Identity header no longer trusted by default** (`X-Dyatel-Sub`): any client
  that could reach the API was able to assert an arbitrary identity, including
  a name from the Authentik admin group, and be provisioned as an admin. The
  path now requires `DYATEL_TRUST_SUB_HEADER=true`, and the panel vhost always
  forwards the header empty.
- **DNS conflicts are 409**: binding a hostname already bound to another
  forward no longer leaks a Postgres unique-violation as `400`.
- **Status surfaces loop errors**: `_error` and `_dns` are included in
  `/status`, so the panel and CLI show reconcile/DNS failures instead of
  silently rendering an empty banner.
- **Ansible**: the core environment file is deployed with `no_log`, so the
  Cloudflare token never appears in play output or diffs.

## [v2.3.5] - 2026-11-27

### Fixed
- **Orphan AWG userspace and config cleanup**: `pruneOrphans` now tears down
  orphan userspace `amneziawg-go` `tun` interfaces (`awd-*`), stops and resets
  their transient `dyatel-awg-*` systemd units, and removes stale rendered
  `wgd-*`/`awd-*` `.conf` files for deleted or suspended hosts while keeping
  active hosts' configs intact.
- **IPv6 NAT chain pruning**: `pruneOrphans` now cleans up orphan `ip6tables`
  `DYATEL-*6` and `DYATEL-*-po6` NAT chains and removes their `PREROUTING` /
  `POSTROUTING` jumps alongside IPv4 `iptables` chains.
- **Degraded-mode loop wiring**: `Reconciler.pass` now invokes
  `ensureFromDisk` when the control-plane database is unreachable so active
  rendered configs are restored on reboot while deleted/suspended configs stay
  absent.
- **Trusted-sub display name preservation**: `Store.CreateUser` no longer
  overwrites an existing human `display_name` when `X-Dyatel-Sub` (or an OIDC
  claim without `name`/`preferred_username`) supplies `authentik_sub` as a
  fallback name, while still upgrading a bare `sub` fallback once a real name
  arrives.

## [v2.3.4] - 2026-11-27

### Added
- **Environment-separated staging networks**: staging runs in
  `10.66.67.0/24` + `fd66:67::/64` (AWG `10.77.78.0/24` + `fd77:78::/64`).
  tiny is attached to both environments, and with a shared subnet the second
  tunnel to come up stole the `...1/32` gateway route from the first - the
  production path went black while staging looked healthy. Production keeps
  `10.66.66`/`10.77.77`.
- **AmneziaWG as the working transport on filtered routes**: plain WireGuard
  between the park's hosts stops passing data (bare UDP and TCP do not), while
  AWG's obfuscated framing passes and holds. The core nodes now get the AWG
  userspace toolkit through `playbooks/dyatel_awg_toolkit.yml`, and a host can
  run WG and AWG side by side (verified: two tunnels to the same peer, `200`
  on both, IPv4 and IPv6).

### Fixed
- **Gateway address self-heal**: an interface keeps the address it was created
  with, so after a network change the gateway stayed on the old subnet while
  peers moved - packets left with a stale source and the peer dropped them.
  The loop converges the interface to the transport's gateway pair and removes
  stale addresses from daemon-owned interfaces.
- **Idempotent deploys**: `go build` now runs with `-buildvcs=false`; with VCS
  stamping a commit between two no-op runs changed the binary checksum and
  bounced the daemon.
- **Pins no longer rejected**: the reserved block was `.1-.15`, which made the
  requested `.6`/`.7` impossible. Only `.1` belongs to the gateway.
- **Authentik SPA OIDC login**: `internal/auth` now validates bearer tokens
  against Authentik's `/application/o/userinfo/` endpoint (preserving
  `/introspect/` compatibility), `dyatel_core` defaults to `userinfo/` and the
  `authentik Admins` group, and `web/src/App.tsx` surfaces OIDC callback errors
  instead of swallowing them silently.

## [v2.3.0] - 2026-11-26

### Added
- **Per-node addressing (migration 0003)**: tunnel addresses and transport
  ports are unique per gateway, not fleet-wide, so berg and glacier may hand
  out the same number to the same peer - it dials them separately and the
  reply route is chosen by destination. Public ports are unique per node too,
  closing a latent DNAT race where two hosts on one gateway could steal each
  other's traffic (`forwards.node` denormalised for the constraint).
- **Pinned addresses and ports**: `preferred_ipv4`, `preferred_ipv6`,
  `preferred_port` on host creation (`dyatelctl hosts create --preferred-*`).
  Pins are validated against the transport's network, the reserved gateway
  block (.1-.15) and the node's allocations, so a duplicate fails loudly
  instead of silently landing on another peer. Pools still bound automatic
  allocation only, which is what makes a memorable 6666/7777 possible.
- **Per-transport tunnel networks**: `DYATEL_TUNNEL_V4_WG/_V6_WG` and
  `_V4_AWG/_V6_AWG` (defaults `10.66.66.0/24`+`fd66:66::/64` and
  `10.77.77.0/24`+`fd77:77::/64`). One peer can now hold symmetric addresses
  on both transports without AllowedIPs or reply routes colliding.
- **IPv6 ingress for forwards**: a parallel ip6tables DNAT/MASQUERADE pair
  against the host's inner v6 address. v6 players were previously refused
  because only the v4 half of the pipeline existed; NAT stays inside its own
  family (v6-to-v4 is NAT64, not DNAT). Verified end to end on staging: a v6
  request lands in the proxer's log as `fd66:66::1`.
- **Placement on another node**: `node` on host creation (admin only), so the
  single management surface can add a lightweight proxer node's hosts without
  hopping to that node's daemon.
- **Degraded data plane**: the pool connects lazily, migration retries in the
  background, and the reconcile loop re-asserts rendered configs from disk
  when the database is unreachable. A node rebooting during a control-plane
  outage no longer comes up dark.

### Changed
- **AWG pins its inner MTU to 1280**: obfuscation eats headroom and IPv6 has
  a hard 1280-byte floor (RFC 8200), so guessing from the underlay produced
  silent loss on obfuscated links. WG keeps automatic MTU.
- **Address rebase (migration 0004)**: existing hosts move into the new
  per-transport networks with their host part preserved, keeping BYOK keys,
  PSKs and gateway keypairs intact.
- **Offline rendering starts at the host block**: `dyatelctl gen` renders the
  first allocatable address (.16 by default) instead of .2, which now belongs
  to the reserved gateway block.

### Fixed
- `store.Open` no longer pings on startup: pgxpool is lazy by design and the
  ping turned a database outage into a dead data plane.

## [v2.2.0] - 2026-11-25

### Added
- **PAT lifecycle in the API and CLI (RFC §3.2)**: `POST/GET/DELETE
  /api/v1/tokens` mint, list and revoke personal access tokens
  (`dyatel_<32 bytes base64url>`). The plaintext secret is returned once
  and never stored — the daemon keeps a SHA-256 digest, because a
  256-bit random secret has no dictionary to attack and the digest must
  stay indexable for auth. `dyatelctl tokens create|list|rm` covers the
  same surface, so scripts no longer need the break-glass admin pair.
- **Post-creation host edits (RFC §5)**: `PATCH /api/v1/hosts/{id}` and
  `dyatelctl hosts edit` change the recorded endpoint, keepalive and the
  invited consumer. BYOK keys stay immutable on purpose: a half-rotated
  keypair has no valid state, so key rotation is delete-and-create.
- **User directory and audit feed**: `GET /api/v1/users?q=` powers
  consumer invitations by display name instead of a raw UUID, and
  `GET /api/v1/events?limit=` exposes the audit trail (`dyatelctl
  users list`, `dyatelctl events`) — scoped to the caller's own actions,
  full feed for admins.
- **`POST /api/v1/reconcile`** (and `dyatelctl reconcile`): force a loop
  pass instead of waiting up to the tick interval.
- **Panel: tokens, activity and onboarding**. New tabs manage PATs
  (with a one-time reveal block), render the audit feed, and hide the
  admin-only drift report from regular users. Registering a host now
  picks the consumer from the searchable directory, and proxer cards
  spell out the exact `wg genkey` → `config` → `wg-quick up` bring-up
  commands with a copy button.
- **`store.User` wire contract**: canonical snake_case JSON tags with
  `authentik_sub` excluded (`json:"-"`), so the directory endpoint cannot
  leak an internal identity key.

### Fixed
- **`last_used_at` poisoned by every PAT request**: the auth path updated
  the timestamp for every token the user owned instead of the one that
  authenticated. `TouchToken` now scopes the update to the presented
  token.
- **Permissions matrix drift (RFC §4)**: the implementation requires the
  **owner** to publish forwards (the person who owns the machine and its
  firewall decides what is exposed), while the document still said
  consumer. The RFC now matches the code, which is also what the panel,
  CLI and the v2.2.0 acceptance path assume.

### Deferred
- DNS records for forwards (Cloudflare upsert, RFC §3.5/§6). Forwards are
  consumed by `IP:port` on the gateway; the `dns_records` table and the
  zone knob already exist so the feature lands without a schema change.

## [v2.1.2] - 2026-11-22

### Fixed
- **Consumer tunnel routes in the reconcile loop (`internal/reconcile`)**: the core installed only the proxer-side route (`ip route replace <host-tunnel-ip> dev <iface>`), so replies to a dial-in consumer left via the default route and died on the LAN — on the test bed the consumer saw a healthy handshake in both directions with every echo request silently lost (`ip route get <consumer-ip>` resolved via `enp5s0`). The loop now installs explicit /32 and /128 routes for the proxer and consumer tunnel IPs of every active host, making the core↔consumer data path real (handshake + echo verified on test).

### Changed
- `ots-cron.yml` switched to the shared catalog stub (`Workflows/ots.yml@v1` + explicit `permissions: contents: write`), eliminating the inline OpenTimestamps job drift; note for the operator: the `BTC_GETBLOCK_KEY` secret is expected in the repository settings (the oracle degrades to single-source with a warning when it is absent).

### Scope note (MVP rollout)
- Production rollout (glacier) ships core + panel; the proxer-side attach (berg node toolkit + forwards) and the panel-driven host management are the next milestone — the API surface is unchanged, so clients registered today keep working.

## [v2.1.1] - 2026-11-15

### Added
- **MIT License (`LICENSE`)**: Added standard permissive open-source license.
- **Example YAML Inventory (`ansible/inventory.example.yml`)**: Added sanitized reference inventory with placeholder domain and connection variables.

### Changed
- **Commit Signing Keys (`.allowed_signers`)**: Restricted `.allowed_signers` strictly to the primary OpenSSH signing key (`danya-git`, `SHA256:zUV6/z1GQKLalAt6WIBOIwgS5TdaQovUVkR+7ItwbZc`), removing secondary and infrastructure keys.
- **Privacy & Inventory Sanitization**: Untracked private production inventory from version control, updated `.gitignore` to match all production and staging inventory patterns.
- **Release Automation (`scripts/release-check.sh`)**: Hardened SemVer tag detection with `--match 'v*'` to prevent collisions with OpenTimestamps proof tags.
- **Documentation**: Expanded bilingual navigation guides in `docs/en/` and `docs/ru/`.

## [v2.1.0] - 2026-11-13

### Added
- **Production inventory (`ansible/inventory.production.yml`)**: Glacier production core node — local PG 15 (`db_manage` one-shot), reuse of the system Xray binary (26.10.31, role skips download when present), `nada.mu` base domain. Masquerade mode stays per-host state in the DB (`params.mode`) set via `dyatelctl`, never Ansible. Panel vhost serves 443 directly (no berg SNI multiplexer): `dyatel_panel_nginx_behind_xray: false` keeps the public HTTPS listener, `dyatel.nada.mu` SPA + same-origin `/api/v1/` proxy.

## [v2.0.0] - 2026-11-13

### Changed
- xray-vless masquerade modes, ported from the Infra Glacier/Floe pattern
  (`hosts.params.mode`): `tls` (default, Floe) keeps xray on the public
  pool port with real TLS plus an optional `fallback host:port` decoy to a
  real local site; `nginx` (Glacier) moves xray to `127.0.0.1` only with
  plain VLESS over WebSocket (`ws_path` masquerade inside the real vhost
  URL space, `public_port` default 443), TLS terminated by the operator's
  nginx — the rendered config carries a `proxy_pass` hint for the vhost
  location. All server inbounds get `sniffing.destOverride
  ["http","tls","quic"]`; client configs dial the masquerade vhost in
  nginx mode instead of the pool port. REALITY rejection and BYOK cert
  placeholders are unchanged; WARP egress, mail-port blocks and DoH DNS
  from the source pattern are deliberately not ported.

### Fixed
- Core API wire format: `store.Host`/`store.Forward` carried no json tags,
  so the daemon emitted Go-default PascalCase (`ID`, `OwnerID`, ...) while
  the panel CLI expected snake_case — every host id decoded as `undefined`
  and follow-up calls failed with `bad id`. Added canonical snake_case tags
  (`json:"-"` on the private/PSK material so it can never leak onto the
  wire) and updated the CLI wire structs and fixtures to match.
- Panel Authentik sign-in button did nothing: `issuer_mode: per_provider`
  means discovery lives at `/application/o/dyatel/.well-known/...`, not at
  the bare authority, so the baked `https://auth.<domain>` root returned an
  HTML page, discovery parsing rejected, and the swallowed rejection looked
  like a dead button. Authority now points at the per-provider issuer path,
  and sign-in/callback failures surface in the login UI instead of being
  dropped.

### Added
- Web panel (`web/`): React 18 + Vite + strict TypeScript SPA served as
  static assets by nginx, talking to the core over the same-origin
  `/api/v1/` mount (no CORS, no separate API hostname — the wildcard
  certificate covers exactly one DNS label, so `api.<domain>` aliasing
  is dropped entirely). Views for proxers (hosts, forwards, consumer
  registration) and clients (forward list, rendered configs).
- Authentication in the panel: Authentik OIDC authorization-code flow
  (public client, `access_token` persisted in sessionStorage) with a
  Basic fallback-admin login validated against `/me` before persisting.
- Ansible role `dyatel_panel`: build-and-ship path mirroring
  `dyatel_core` (npm build on the control host, dist to
  `/var/www/dyatel-panel`), nginx vhost behind the berg L4 SNI
  multiplexer (loopback bridge + PROXY protocol v2 real IPs), paired
  `panel.yml` / `panel_uninstall.yml` playbooks with stale-asset pruning.
- Authentik blueprint entry (Infra) for the `dyatel` application with a
  single strict redirect URI `https://dyatel.<domain>/`; Vaultwarden sync
  item for the core fallback admin points at the same origin.

### Added
- `dyatelctl gen`: offline config rendering, making Tier 0 literal — a
  proxer deploys themselves with just the ansible playbook plus `gen`,
  no daemon, no PG, no Authentik (those stay a Tier-1 convenience).
  `gen wireguard` renders berg/proxer/client wg-quick configs
  (wireguard or amneziawg, fresh PSK + berg keypair by default), `gen
  xray` renders the berg aggregate, the proxer note and the client
  dokodemo-door config from a `public:target[:proto]` forwards spec
  (`--mode/--ws-path/--public-port/--fallback` pick the masquerade).
  Enablers: wg keypair/PSK generation moved from reconcile into the
  Tier-0 transport package (`wireguard.GeneratePSK` /
  `GenerateKeypair`), and `config.LoadForRender` exposes the
  env-driven defaults (nets, port pools, endpoint) without the DSN
  requirement — the CLI never imports reconcile internals, only pure
  transport renderers.
- xray-vless berg bring-up: the reconciler now renders one aggregate
  xray config per node (`RenderServerConfigMulti`, one vless inbound per
  host, single freedom outbound), compares it byte-wise to the on-disk
  `/etc/xray/dyatel.json` and atomically rewrites + restarts `xray@dyatel`
  only on diff; an empty host set stops the unit (and a live-but-stopped
  unit is started back), so suspended hosts drop out of the aggregate and
  lose their UFW allow in the same pass. Reality is rejected at parse
  time everywhere: VLESS runs strictly as a TLS masquerade (Reality is
  unusable in Russia). BYOK stays: without `cert_file`/`key_file` the
  config embeds PEM placeholders for the operator to substitute on the
  berg, so the core never holds TLS private keys.
- Ansible role `dyatel_core`: pinned xray release install (only when
  the binary is absent; never removed on uninstall since xray may be
  shared with other instances on the host), `xray@dyatel` template unit
  (enabled but not started — the core starts it once it has rendered a
  valid aggregate config), paired uninstall of unit + config, and
  `DYATEL_XRAY_CONFIG_PATH`/`DYATEL_XRAY_SERVICE` env plumbing.

## [v1.1.0] - 2026-11-13

### Added
- `dyatelctl` CLI (cobra + carapace completions): `me`, `status`, `hosts`
  (`list|create|show|rm|state|register-consumer-key|config proxer|client`),
  `forwards` (`list|create|rm`) — the first real consumer of the
  `/api/v1` daemon API, proving the core surface is usable without
  daemon internals. `--json` passthrough, `--out FILE` (mode 0600) for
  client configs, `DYATEL_*` env fallbacks.
- `internal/client`: thin HTTP transport for the daemon API (Bearer PAT
  wins over Basic fallback admin); `APIError` surfaces daemon
  plain-text error bodies verbatim; no imports of reconcile/store/auth.
- Ansible role `dyatel_core` ships `dyatelctl` alongside the core binary
  (same checksum-gated build-and-ship path).
- Proxer-side UFW contract for AmneziaWG replies, documented in RFC §6
  after the live awg-smoke run (gw replies source from the gw LAN
  address; consumer-side UFW must allow them from both paths).
- `xray-vless` transport (RFC §3.4a): typed config renderer with plain
  TLS masking only — Reality is rejected at params parse time and every
  output path is asserted Reality-free. `dyatelctl hosts config proxer`
  returns an ops note (no per-forward config on the leg), `client`
  renders dokodemo-door inbounds + routing rules per forward. UUID
  injection at create, BYOK cert placeholders by default.
- Reconcile opens `listen_port/tcp` for `xray-vless` hosts (the pool
  allocates from 5200-5299/tcp) and skips tunnel-interface provisioning
  entirely: xray terminates the leg, the protocol carries the
  destination, no NAT/DNAT needed.

### Fixed
- `POST /hosts/` responses now carry the initial `state` ("active"):
  the insert hard-codes it but RETURNING only filled ID, so the
  serialized host lost it.

### Fixed
- Empty API collections serialize as `[]` instead of `null`.
- Reconcile masquerades forwarded traffic to the gw tunnel IP
  (per-iface `DYATEL-<ifname>-po` chains off POSTROUTING).
- Consumer-only AWG hosts render without berg-side key material;
  userspace `amneziawg-go` fallback and tool dispatch in `Status`.

## [v1.0.1] - 2026-11-13

### Fixed
- Gateway role now reconciles UFW route rules: forward rules pointing at
  obsolete client IPs (left over from deployments with different
  `dyatel_gateway_*_client_ip` overrides) are removed automatically on every
  run of the WireGuard and AmneziaWG transport modules.
- Gateway teardown (`dyatel_gateway_state: absent`) now removes all Dyatel
  UFW route rules, including stale ones, instead of leaving them behind.
- `ansible.cfg` collections path no longer references the stale
  `/Projects/Infra/collections` checkout location; `collections_path` now
  points at the canonical `/root/.ansible/collections` install root.
- The duplicate `ansible/ansible.cfg` is aligned with the root config and
  now also sets `collections_path`, so runs started from `ansible/` resolve
  `community.general` identically.

### Changed
- `scripts/install.sh` now detects the system package manager (apt,
  pacman, dnf) instead of assuming apt, so gateway/node bootstrap works
  on Debian, Arch-based, and RHEL-based hosts.

## [v1.0.0] - 2026-11-10

### Added
- Multi-transport NAT traversal and game proxy suite for self-hosted dedicated servers.
- High-performance WireGuard L4 forwarding module (`wg-dyatel`) with sub-millisecond latency.
- AmneziaWG obfuscated transport module (`awg-dyatel`) powered by userspace `amneziawg-go` for DPI/TSPU evasion.
- Kernel-space TCP MSS clamping (`TCPMSS --clamp-mss-to-pmtu`) eliminating MTU fragmentation over UDP tunnels.
- Dual-stack IPv4 DNAT and direct routed IPv6 forwarding.
- Strict perimeter firewall isolation rules preventing client nodes from accessing host management ports or private subnets.
- Standalone one-click zero-dependency installer (`scripts/install.sh`) supporting `--role gateway` and `--role node`.
- Modular, pluggable Ansible roles: `dyatel_gateway` and `dyatel_node`.
- Turnkey deployment playbooks: `site.yml`, `gateway.yml`, `node.yml`, `uninstall.yml`.
- Standard project baseline with OpenTimestamps cryptographic anchoring.
- Bilingual documentation in English (`README.md`) and Russian (`README.ru.md`).
