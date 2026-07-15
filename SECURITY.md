# Security Policy

## Reporting A Vulnerability

Report suspected vulnerabilities privately to <security@borgels.com>.

Do not include API keys, access tokens, personal data, accounting data, customer
data, or other secrets in public GitHub issues. Include a concise description,
affected package/version, reproduction steps, and impact where possible.

## Supported Versions

Security fixes are targeted at the latest `main` branch and the latest published
release, when one exists.

## Credential Handling

This MCP server reads provider credentials only from the server environment and
does not accept credentials as tool arguments. If you believe credentials were
exposed, rotate them with the upstream provider immediately.
