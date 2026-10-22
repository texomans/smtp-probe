# Security model — public beta

SMTP Probe has **not** received an independent security audit. Use TLS, a strong password and network-level controls before allowing Internet access.

## Implemented controls

- Required page password, minimum 15 by default (configurable 1–512); startup validation and warning below 15.
- Secure host-only HttpOnly SameSite=Strict cookies for HTTPS, hashed session tokens, eight-hour session expiry, server-side logout and CSRF protection.
- Login throttling, same-origin checks, per-IP/target/account test limits and concurrency caps.
- Public-target IP/DNS checks, pinned resolved address, blocked private networks/IP literals and an SMTP port allowlist.
- Verified TLS required for authentication; certificate and hostname verification cannot be disabled in the UI.
- Redacted authentication payloads and email body in transcripts.
- Email sending off by default, explicitly enabled only with administrator-approved recipients and authenticated TLS.
- Nonroot, read-only container with resource caps and dropped Linux capabilities in the provided Compose files.

## Limitations

Arbitrary public SMTP servers are intentionally supported, creating potential credential-guessing or outbound abuse if access is compromised. Application limits are in-memory and reset on restart, and cannot replace host/provider egress controls.

A shared password cannot provide per-user accountability. The HTTPS reverse proxy must sanitize forwarding headers and be trusted; never publish application port 3000 directly. SMTP `250` means server acceptance, not guaranteed delivery.

Use a separate staging installation, pin production image versions, keep OS/container/proxy dependencies patched, and never commit passwords, `.env` files, saved customer email or logs. Even redacted transcripts may reveal sensitive domains and addresses. Report security concerns privately to maintainers.
