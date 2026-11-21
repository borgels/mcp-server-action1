# mcp-server-action1

MCP server for the [Action1](https://www.action1.com/api-documentation/) endpoint management (RMM/patching) REST API 3.0.

This is an independent, unofficial project. It is not developed, endorsed or supported by Action1.

> **Disclaimer:** "Action1" and the
> Action1 API are referenced only to describe what this server talks to. You need
> your own Action1 credentials, and use of the Action1 API is subject to Action1's
> own terms.

## Tools

**Read (always on):** organizations, managed endpoints (inventory, status filters, missing updates), endpoint groups, updates/patches (approval status, severity), vulnerabilities (CVEs, affected endpoints, remediations), installed software, software repository, script library, automations (schedules and run history with per-endpoint results), reports + report data, enterprise audit log, capability discovery.

**Write (opt-in via `ACTION1_ENABLE_WRITES=true`):** `action1_set_update_approvals` — approve/decline updates for one organization (the patch-approval workflow). `orgId="all"` is refused.

**Deliberately absent (RMM safety):** creating or running automations (`run_script`/`deploy`/`reboot` — remote code execution on endpoints), remote-desktop sessions, software-repository modification (supply-chain risk), endpoint delete/move, user/role/organization management, enterprise closure. If script execution is ever needed it should be a separate duty-gated commit tool.

## Auth & regions

OAuth2 client-credentials against `{base}/oauth2/token`; tokens live exactly 3600 s and are cached/renewed automatically. Credentials are created in the Action1 console under Configuration → Users & API Credentials. Set `ACTION1_BASE_URL` to your data-center region (EU: `https://app.eu.action1.com/api/3.0`).

## Pagination & rate limits

Lists return `{items, total_items, from, nextFrom}` — pass `nextFrom` as `from` to continue. Action1 recommends staying under ~30 requests/minute per enterprise; 429 responses surface `retry-after`.

## Install

```bash
npx mcp-server-action1
```

Runs the stdio server from npm. Configure it with the environment variables in `.env.example`.

## Run

```bash
npm install
npm run dev          # stdio
npm run dev:http     # streamable HTTP on :3000/mcp (stateless)
npm test
```

Docker images: `ghcr.io/borgels/mcp-server-action1` (`latest` and the commit SHA from `main`, version tags from `v*`; published only after CI passes).

## HTTP transport

`npm run dev:http` (or the Docker image) serves `POST /mcp` and an unauthenticated
`GET /healthz`. It binds to `127.0.0.1` unless `MCP_HTTP_HOST`/`HOST` says otherwise.

| Env var | Default | |
|---|---|---|
| `MCP_HTTP_TOKEN` | - | Bearer token callers must present on `/mcp` (constant-time compare); at least 32 printable ASCII characters (e.g. `openssl rand -hex 32`). **Required** on a non-loopback bind (e.g. `0.0.0.0` in a container) and with `MCP_ALLOW_ANY_ORIGIN=true`; the server refuses to start otherwise. |
| `MCP_HTTP_ALLOW_UNAUTHENTICATED` | `false` | Serve `/mcp` without a token on a non-loopback bind. Only if access is restricted by other means. |
| `MCP_HTTP_HOST` / `HOST`, `PORT` | `127.0.0.1`, `3000` | Bind address and port. |
| `MCP_MAX_BODY_BYTES` | `10485760` | Request body limit. |
| `MCP_ALLOWED_ORIGINS` / `MCP_ALLOW_ANY_ORIGIN` | localhost origins | Browser origins allowed to call `/mcp`. |
| `MCP_ALLOWED_HOSTS` | localhost names on a loopback bind | Host names accepted in the `Host` header (DNS-rebinding protection). |
| `MCP_AUTH_FAILURE_LIMIT` / `MCP_AUTH_FAILURE_WINDOW_MS` | `20` / `60000` | Failed authentication attempts per client address before `429`; `0` disables. Valid tokens are never throttled. |

`PORT`, `MCP_MAX_BODY_BYTES`, `ACTION1_TIMEOUT_MS` and the boolean flags are validated at
startup; an invalid value stops the server with a message naming the variable.

## Security notes

- Caller-supplied ids are validated before they are placed in API paths (strict id / `CVE-YYYY-NNNN` patterns, no dot segments or separators), and every request URL must stay under the configured `ACTION1_BASE_URL` path.
- API and token requests never follow HTTP redirects, so the bearer token and `client_secret` are only sent to `ACTION1_BASE_URL`. Upstream error bodies are read up to 64 KB and redacted before they are truncated.
- Audit log entries (`ACTION1_AUDIT_LOG`) include a `caller` field taken from the `X-MCP-User` header when an upstream gateway forwards one. It is informational and only trustworthy when the server is reachable solely through that gateway (use `MCP_HTTP_TOKEN`).

## Embedding (`./gateway`)

The package also exports an embeddable gateway for hosts (such as an MCP gateway with its own per-user authorization) that run one instance per tenant in one process:

```ts
import { createAction1Gateway, action1ToolCatalog } from 'mcp-server-action1/gateway';

const gateway = createAction1Gateway({
  clientId,          // the API client id (Action1 shows it as an e-mail-like id)
  clientSecret,      // the API client secret
  region: 'eu',      // eu | na | na2 | uk | au: one of Action1's fixed API addresses
  policy: { enableWrites: false, disabledTools: [], audit: record => log(record) },
});
const result = await gateway.callTool('list_endpoints', { orgId }, { caller: userId });
```

- **Nothing from the environment.** An instance reads no `ACTION1_*` variable: not the credentials, not `ACTION1_BASE_URL` (the region picks a fixed address; there is no free address), not the time limit (30 s unless `timeoutMs` is given), not `ACTION1_ENABLE_WRITES` or `ACTION1_AUDIT_LOG`.
- **Credentials.** The client secret passes key admission (printable ASCII, at least 16 characters, no 6-character piece shared with the package's own texts; refused without being quoted). The client id is checked for form and redacted as a whole value. The access and refresh tokens Action1 issues are added to the instance's redactor before use. Every result, error and audit record is redacted, and the sink check withholds any output that still holds a piece of a secret.
- **Network.** Only the region's API address; redirects are never followed; Action1's response bodies are never read into an error (errors start with `Action1 API request failed with HTTP <status>` and our own hint).
- **Policy.** `{ enableWrites, disabledTools, audit }` from the host (default: no writes, nothing disabled, no audit). The audit sink gets the caller as an HMAC pseudonym, the ids as a hash and errors as fixed codes; a tool whose start record fails does not run.
- **Failures.** An error result caused by an HTTP error from Action1 (or a refused redirect) carries `failure: { httpStatus, requestId? }`: the status, and Action1's request id only when a response header gives one as a UUID or hex id. Never the response body, Action1's error text or the input.
- **Catalog.** `action1ToolCatalog` is deeply frozen and lists, per tool, the definition, `upstream` (every Action1 request it may make, relative to `…/api/3.0`) and `broad` (false for all).

Tools (reads are enabled by default, the writes are not):

| Tool | Kind | What |
| --- | --- | --- |
| `search_capabilities` | read | The tools this instance offers. |
| `check_connection` | read | Token request and a count of organizations. |
| `list_organizations` | read | Id, name, description. |
| `list_endpoints`, `get_endpoint` | read | Computers: name, OS, status, last seen, reboot required, update and vulnerability status, counts of missing updates, logged-in user name (left out when it is a mail address); optionally the missing updates. Never IP or MAC addresses, serials, directory groups, custom attributes or comments. |
| `list_endpoint_groups` | read | Groups (id, name, description) and their members. No filters or notification settings. |
| `list_updates` | read | Missing updates with versions, severity, approval status and patch deadline. No install switches or binaries. |
| `list_vulnerabilities` | read | CVEs with score, CISA KEV, remediation status, affected software; affected computers; recorded remediations (who by display name only). |
| `get_installed_software` | read | Name, vendor, version, platform, number of computers, update status. |
| `list_reports`, `get_report_data` | read | Reports and their rows: only named inventory, update and vulnerability columns, and never a value that looks like a mail, IP or MAC address (a version column keeps four numbers with dots as a version). |
| `list_automations` | read | Automations an administrator has set up and their runs: id, name, status, schedule, last and next run, targets (ids and types), action names and templates; the status of a run on each computer. Never the action parameters (script text included) or a run's output. |
| `list_software_repository` | read | Deployable packages (id, name, vendor, description, platform) and their versions. No install switches or files. |
| `set_update_approvals` | write | Approve, decline or reset to New update versions in one organization (never `all`). Nothing is installed by the call. |
| `deploy_updates` | write | Install missing updates now on named computers or groups (1-50) in one organization. No restart unless `allowReboot`; then Action1 warns the user and restarts after four hours if needed. |
| `deploy_software` | write | Install a package from the software repository now on named computers or groups (1-50) in one organization, without a restart. |
| `run_automation` | write | Run an automation an Action1 administrator has already set up, now, with its own actions (which may run scripts, deploy software or restart computers), on its own targets or only on named computers or groups (1-50). Its own targets are held to the same rules: an automation set up for every computer, for more than 50 targets or with filters is run only on named targets. |

A run always belongs to one organization; `all` is refused as organization and as target, and every target is a named computer or group (for `run_automation` without targets, the automation's own, checked the same way). `rebootMessage` (option) is the text Action1 shows before `deploy_updates` restarts a computer, for example in the company's language. No tool writes a script or an action: `run_automation` sends the automation's actions back to Action1 as Action1 gave them and never returns them. Nothing in the gateway removes software, opens remote sessions, changes settings, users or roles, or deletes; the script library and the audit log are not offered. Which roles get the writes is the host's decision.

## Security model

- The server acts with **one shared Action1 API identity** (the configured client
  id/secret). Every MCP client that can call it gets that identity's access.
- Per-user authorization belongs in an identity-aware gateway in front of the
  server; `MCP_HTTP_TOKEN` authenticates the caller as a whole, not individual users.
- Tool access is not data access: limiting the tool list (for example with
  `ACTION1_ENABLE_WRITES`) does not limit what the API credentials may read or change.
  Scope the Action1 API credentials accordingly.
- The HTTP server does not terminate TLS. Put it behind a TLS-terminating proxy
  or keep it on a private network.
- Run one instance per Action1 organization you want to expose, each with its own
  credentials and token.

## License

The code is source-available under the [Functional Source License, Version 1.1, ALv2 Future License](LICENSE) (FSL-1.1-ALv2).

In plain words:

- **Allowed:** reading the code, running it, changing it, using it inside your own organisation (also commercially), using it for non-commercial education and research, and contributing changes back.
- **Not allowed:** making it, or something built from it, available to others as a commercial product or service that competes with it, for example a hosted service with the same functionality.
- **Becomes Apache-2.0:** each version is also licensed under the Apache License 2.0 from two years after it is released.
- **Earlier versions:** versions released before 0.5.0 were licensed under Apache-2.0 and remain so.

The terms in [LICENSE](LICENSE) are what apply; this summary does not replace them. See also [NOTICE](NOTICE).
