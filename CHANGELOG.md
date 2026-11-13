# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
