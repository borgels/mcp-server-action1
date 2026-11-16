# Changelog

## 0.3.0

### Upgrade notes

- The HTTP server refuses to start on a non-loopback bind (`MCP_HTTP_HOST`/`HOST`,
  e.g. `0.0.0.0`) or with `MCP_ALLOW_ANY_ORIGIN=true` unless `MCP_HTTP_TOKEN` is set.
  `MCP_HTTP_ALLOW_UNAUTHENTICATED=true` restores the old behaviour explicitly.
- `MCP_HTTP_TOKEN` must be at least 32 printable ASCII characters.
- `PORT`, `MCP_MAX_BODY_BYTES`, `ACTION1_TIMEOUT_MS` and boolean flags such as
  `MCP_ALLOW_ANY_ORIGIN` are validated at startup; invalid values stop the server
  instead of being read as `NaN`.
- The `Bearer` scheme in `Authorization` is matched case-insensitively.
- The `deploy/` examples were removed; see the README for the HTTP settings and
  security model.

### Changes

- HTTP transport: failed-authentication limiting per client address (`429` with
  `Retry-After`; new `MCP_AUTH_FAILURE_LIMIT`, `MCP_AUTH_FAILURE_WINDOW_MS`), `Host`
  header check on loopback binds (new `MCP_ALLOWED_HOSTS`), `401` with
  `WWW-Authenticate`, `400` for invalid JSON, `413` before reading an oversized
  body, `GET /healthz`, graceful shutdown on `SIGTERM`/`SIGINT`.
- API and OAuth token requests no longer follow redirects, so the bearer token and
  `client_secret` cannot be re-sent to another host.
- Upstream error bodies are read up to 64 KB; error text is redacted before it is
  truncated.
- The server reports the package version (it reported `0.1.0`).
- Removed an unused forwarded-user helper.
- Docker image is published only after CI passes, with SBOM and provenance; GitHub
  Actions are pinned to commit SHAs; dependency updates.

## 0.2.0

- Add self-hosting examples for one instance per Action1 organization.
- Add a README disclaimer clarifying this is an independent, unofficial project.
- Bump transitive dependencies (`hono`, `@hono/node-server`, `fast-uri`,
  `ip-address`) to close known advisories; `npm audit --omit=dev` is clean.

## 0.1.0

Initial release.

- 15 tools against the Action1 REST API 3.0 (EU/NA/AU regions): organizations,
  endpoint inventory (+ missing updates), endpoint groups, updates/patches,
  vulnerabilities (CVE detail/endpoints/remediations), installed software,
  software repository, script library, automations (schedules + run history),
  reports + report data, audit log, capability discovery.
- One write tool: patch approvals (single org only), gated behind
  ACTION1_ENABLE_WRITES=true.
- Deliberately NOT exposed: creating/running automations (remote code
  execution), remote-desktop sessions, software-repository writes,
  endpoint delete/move, user/role/org management.
- OAuth2 client-credentials with automatic token caching/renewal (3600 s
  tokens); 429 rate-limit surfacing with retry-after.
