# Dyatel — Project Agent Rules

Dyatel is a tunnel/proxy control panel: a Go core daemon reconciling WireGuard /
AmneziaWG / Xray tunnels from Postgres state, with CLI and web panel as thin
consumers. Read `docs/RFC-core.md` for the domain contract before touching the
core, and update the affected sections of `docs/RFC-core.md` in the same PR
when changing DB schema, `/api/v1`, addressing rules, or reconcile invariants.

## Non-Negotiables

- **Global rules apply**: `~/Projects/Agent/AGENTS.md` is the user-global ruleset
  (auth delegation, break-glass admin, core → CLI → GUI order, secrets policy).
  When in doubt, it wins over local convenience.
- **No user private keys in the core** (BYOK): owners and consumers generate
  keypairs locally and submit public keys only. The core generates only the PSK
  and its own berg-side keypair.
- **No local user store**: authentication is Authentik (OIDC) + PATs issued by
  the core on top of it; exactly one break-glass admin (`authentik_sub = null`).
- **We do not own Postgres**: the core runs against an existing PG instance; it
  never provisions or manages the database server itself.
- **Roles are for humans**: `проксер` = host owner, `клиент` = host consumer;
  the same person can be both. The core never separates them into different
  subsystems.
- **No backward compatibility**: break the API freely inside a milestone, bump
  semver, document in `CHANGELOG.md`.

## Module Boundaries

1. `cmd/dyateld` — core daemon (API `/api/v1` on 127.0.0.1:8100 only, reconcile
   loop every 15s, embedded migrations).
2. `internal/*` — storage, auth (Basic fallback / Bearer OIDC / PAT
   `dyatel_*` / trusted `X-Dyatel-Sub`), reconcile (wg syncconf, per-iface nat
   chains, ufw want-map sync, orphan pruning), DNS.
3. `cmd/dyatelctl` — CLI consumer (cobra + carapace), talks to the daemon API.
   Never imports reconcile internals.
4. Web panel — React, phase 3; same API, no daemon internals.

The core never imports interface code; interfaces never bypass the API.

## Ansible

- Deployment lives in `ansible/`: role `dyatel_core` (Ansible's job — files,
  units, drop-ins), playbooks `core.yml`. Runtime peers/transports/UFW/NAT/DNS
  stay in core code, never in Ansible templates.
- `dyatel_gateway` on test is FROZEN at v1.0.1 — do not modify without the
  user's explicit say-so.
- Testbed-first: everything lands on `test` (Berg) and reaches `changed=0`
  idempotency before merge; production deploys only via signed tags + CHANGELOG.
- Secrets only via `Infra` vault (`CHANGE_ME_*` placeholders here); never in
  this repo. UFW, not raw iptables. systemd units, not cron.

## Conventions

- Go toolchain matches `go.mod` (`go test -race ./...`, `go vet ./...`);
  Postgres-backed integration tests in `internal/api` and `internal/client`
  run when `DYATEL_TEST_DSN` is set.
- Web panel (`web/`): strict TypeScript (`cd web && npm ci && npm run build`).
- Commits: Conventional Commits, English, SSH-signed (`danya-git`),
  `git -c user.name=Danya -c user.email=git@nada.mu commit`.
- Docs: bilingual `docs/en/` + `docs/ru/` for user-facing material; RFC and
  code comments in English.