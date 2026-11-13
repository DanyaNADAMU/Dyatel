# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
