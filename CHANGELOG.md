# Changelog

## v0.2.0-beta.1 — SMTP Probe public beta preparation (2026-10-21)

- Renamed **SMTP Scope** to **SMTP Probe** across the application, SMTP headers, diagnostics, container identity, and public documentation.
- The single application version in `package.json` now drives the API version and both UI labels.
- Added GHCR publication workflow for `linux/amd64` and `linux/arm64`: version tag plus moving `beta` (only stable releases get `latest`).
- Added pull-only Compose resources for Komodo: **version-pinned VPS/NPM** and **loopback-only home staging**. Email sends are disabled by default.
- Added repository and Komodo release/migration guides and container package metadata.
- Kept legacy `SMTP_SCOPE_PASSWORD`, `SMTP_SCOPE_PASSWORD_MIN_LENGTH`, and `SMTP_SCOPE_COOKIE_SECURE` environment variables working while adopting the new `SMTP_PROBE_*` names. A restart clears old sessions.
- Updated public gateway and authentication scripts for `smtpprobe.texomans.com`.
- Preserved functional SMTP/TLS/login/send protections, diagnostic reporting, wildcard recipient lists, and blank hostname input from v0.1.6.

This is a **public beta candidate**, not an independently security-audited general-availability release.
