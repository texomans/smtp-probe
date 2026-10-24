# Changelog

## v0.2.0-beta.4 — 2026-10-24

- Added an independent SPF, DKIM and DMARC DNS diagnostic workspace and authenticated API.
- Inspect SPF records, include/redirect chains, common syntax issues, cycles and static lookup-term warnings without claiming sender-IP authorization.
- Inspect supplied DKIM selectors, delegated TXT keys, RSA/Ed25519 public-key parsing, strength, revocation and restrictions without claiming signature verification.
- Discover direct/inherited DMARC policies and organizational boundaries using RFC 9989 tree walks; show strict/relaxed potential identity alignment and legacy-receiver caveats.
- Added separate DNS copy/download reports, query traces and explicit unknown/not-tested states.
- Bound DNS work by request deadlines, query/response/expansion limits, concurrency and independent rate limits. Added deterministic DNS protocol, parser, API, UI/export and container regression checks.
- Deployment image pins remain unchanged; select the approved release explicitly using SMTP_PROBE_IMAGE.

## v0.2.0-beta.3 — 2026-10-24

- Added a versioned security grading policy with explained TLS, certificate, cipher and expiry findings.
- Added separate TCP, banner, EHLO, TLS, authentication and submission outcomes with explicit untested states.
- Added advertised authentication and SMTP capability summaries without treating advertisement as proof of acceptance.
- Added the scorecard to the UI and redacted copy/download reports, including test scope and limitations.
- Added grading policy, UI/export and SMTP integration regression coverage. Deployment image defaults remain unchanged pending publication and upgrade.

## v0.2.0-beta.2 — 2026-10-24

- Startup logging now reads the application version from package.json, matching the API and UI.
- Image publishing rejects version tags that do not match package.json; beta images cannot receive the stable `latest` alias.
- CI now smoke-tests the built container in an isolated network, verifying health, login/logout and version reporting with sending disabled.
- Docker and Docker Compose now serve as the primary, vendor-neutral deployment options, pulling prebuilt images by default.
- Added optional Komodo, Portainer, Nginx Proxy Manager, Traefik, Caddy and Nginx installation instructions.
- Introduced generic HTTPS Compose using an administrator-chosen external proxy Docker network.
- Removed historical product aliases, old-name references and migration-specific instructions.
- Removed operator-specific website defaults from public HTTPS test scripts.
- SMTP sending remains disabled by default.

## v0.2.0-beta.1 — first public beta

- Published GitHub Actions workflows for source tests and multi-architecture GHCR images.
- Included SMTP diagnostics, TLS and certificate inspection, authentication and optional controlled test-email submission.
- Included server-side login, CSRF protection, session handling, rate limits and redacted exports.

The application remains a public beta and is not independently audited.
