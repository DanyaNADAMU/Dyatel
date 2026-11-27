---
description: "React, Vite, and TypeScript panel instructions for Dyatel"
applyTo: "web/**"
---

# Web Panel Instructions (`web/`)

- TypeScript runs in strict mode (`tsc -b` with `noUnusedLocals` and
  `noUnusedParameters`). Always verify with `cd web && npm run build`.
- Keep `web/src/types.ts` and `web/src/api.ts` strictly aligned with the Go
  backend `/api/v1` JSON tags in `internal/store/store.go` and
  `internal/api/api.go` — do not add silent fallback field aliases.
- Authentication flows through Authentik OIDC (`oidc-client-ts`) plus the
  single break-glass admin login; never introduce a local user registration or
  password store.
- User-facing copy in the web panel must stay consistent with existing language
  handling and never hardcode production hosts or tokens.
