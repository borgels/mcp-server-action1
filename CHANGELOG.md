# Changelog

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
