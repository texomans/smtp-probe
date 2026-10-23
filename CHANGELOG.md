# Changelog

## v0.2.0-beta.2 — pending release

- Startup logging now reads the application version from package.json, matching the API and UI.
- Image publishing rejects version tags that do not match package.json; beta images cannot receive the stable `latest` alias.
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
