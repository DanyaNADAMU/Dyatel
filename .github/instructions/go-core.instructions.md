---
description: "Go daemon, CLI, storage, and reconcile rules for Dyatel"
applyTo: "**/*.go,migrations/**"
---

# Go Core & Migrations Instructions

- Keep strict layer isolation:
  - `cmd/dyatelctl` talks to `cmd/dyatel-core` over `/api/v1` via
    `internal/client`; never import `internal/reconcile` or `internal/store`
    into CLI production code.
  - Pure config rendering (`dyatelctl gen`, `internal/transport/*`,
    `config.LoadForRender`) must work offline without `DYATEL_DB_DSN`.
- Wire contracts: `store.Host`, `store.Forward`, and `store.User` JSON tags are
  the public `/api/v1` wire format. Keep `internal/client/client.go` and
  `web/src/types.ts` in sync whenever fields change.
- Migrations (`migrations/*.up.sql` / `*.down.sql`): every schema change must
  include a matching reversible `.down.sql` migration.
- Reconcile & Pool safety:
  - Preserve degraded data-plane behavior (tunnels stay up when DB is down).
  - Never expose `GWPrivateKey` or `WGPreSharedKey` in API JSON responses.
  - Cover logic changes in `internal/pool`, `internal/reconcile`, `internal/auth`,
    and `internal/api` with table-driven tests (using interfaces/mocks for OS
    commands and DB reads where appropriate).
