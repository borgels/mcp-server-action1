# Contributing

Improvements are welcome: new or better tools, wider coverage of the upstream
API, bug fixes and documentation.

This is an independent, unofficial project. It is provided as is: there is no
support agreement or response time, and not every change will be merged.

## Issues

- Open a GitHub issue for bugs and feature requests. Say which tool you called,
  what you expected, what happened, and the version you run.
- Never put API keys, tokens, personal data, customer data or real account
  data in issues, pull requests or commit messages. Use placeholders such as
  `user@example.com`, `<tenant-id>` or `192.0.2.10`.
- Security problems go privately to the address in [SECURITY.md](SECURITY.md),
  not in an issue.

## Pull requests

1. Fork the repository and branch from `main`.
2. Keep a pull request to one change. Update the README, CHANGELOG and example
   configuration when behaviour or configuration changes.
3. Run the same checks as CI before you push:

   ```sh
   npm ci
   npm run typecheck
   npm test
   npm run build
   ```

4. Open the pull request against `main`. Pull requests are squash-merged.

Every pull request runs CI and a public-hygiene check that scans the added
lines, file names, commit messages and the pull request text for secrets,
personal data and internal names. A pull request is public as soon as it is
opened, so check your changes before you push.

## Ground rules

- Credentials come from the server environment, never from tool arguments.
- Do not weaken the authentication, per-user isolation, write gates or
  redaction described in the README and SECURITY.md.
- Add or update tests for every change.

## License

By contributing you agree that your contribution is licensed under the
Apache License 2.0, the same as the project (see [LICENSE](LICENSE)).
