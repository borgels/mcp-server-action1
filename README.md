# mcp-server-action1

MCP server for the [Action1](https://www.action1.com/api-documentation/) endpoint management (RMM/patching) REST API 3.0.

> **Disclaimer:** This is an independent, unofficial project by Borgels. Borgels is
> not affiliated with, endorsed by, or supported by Action1. "Action1" and the
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

## Run

```bash
npm install
npm run dev          # stdio
npm run dev:http     # streamable HTTP on :3000/mcp (stateless)
npm test
```

Docker images: `ghcr.io/borgels/mcp-server-action1` (published on push to `main`).

## Deploy

See `deploy/` for the docker-compose service block, `hosts.json` entries, a reverse-proxy
site block, and example env files — one instance per Action1 organization you want to
expose, fronted by whatever OAuth-aware gateway/reverse-proxy sits in front of your fleet.
