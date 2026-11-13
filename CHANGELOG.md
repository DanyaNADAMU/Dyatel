# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- Gateway role now reconciles UFW route rules: forward rules pointing at
  obsolete client IPs (left over from deployments with different
  `dyatel_gateway_*_client_ip` overrides) are removed automatically on every
  run of the WireGuard and AmneziaWG transport modules.
- Gateway teardown (`dyatel_gateway_state: absent`) now removes all Dyatel
  UFW route rules, including stale ones, instead of leaving them behind.

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
