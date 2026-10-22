# SMTP Probe security model (beta)

**Scope:** Password-protected SMTP testing app, deployed behind a properly configured TLS-terminating reverse proxy. **Not independently audited.** No claim of production security certification is made.

## Controls implemented

- All SMTP API operations are protected by the same server-side session check as the browser UI; cookie is `__Host-smtp_probe_sid` on HTTPS, with HttpOnly, Secure, SameSite=Strict and no Domain attribute.
- Session tokens are random and stored as hashes, expire after 8 hours, and logout deletes server-side session state. Sessions do not survive restart.
- POST endpoints require session-aware CSRF protection (except login), and cross-origin requests are rejected.
- Shared password minimum default is 15 characters, configurable by administrators via `SMTP_PROBE_PASSWORD_MIN_LENGTH` (or legacy `SMTP_SCOPE_PASSWORD_MIN_LENGTH`); passwords below 15 trigger warnings.
- Incorrect passwords are throttled, with per-IP and global counters. Test rate limits use per-IP, per-SMTP-host, and hashed-account keys; active tests are concurrency-limited.
- DNS hostnames are resolved and checked for public addresses before socket connection; IP literals, local/private/reserved network addresses, and several address translation escapes are blocked. Allowed ports are restricted.
- AUTH is never attempted in plaintext mode. TLS certificate verification and hostname checks are enabled; no 'ignore invalid certificate' switch.
- SMTP credentials do not go in application logs or `.env`. The transcript redacts SMTP authentication payloads and email DATA. One send request permits one recipient, with server-enforced recipient allowlists, and requires explicit admin opt-in (`ALLOW_SEND=1`).
- The image runs as a non-root user, drops all Linux capabilities in Compose, with a read-only filesystem, bounded tmpfs and resource limits; no database, no third-party Node runtime packages.
- Public Komodo Compose publishes **no host ports**. A reverse proxy on the same Docker network is responsible for HTTPS and correct client IP forwarding.

## Risks not eliminated

- Arbitrary **public** SMTP destinations are deliberately supported (intended utility), which creates credential-guessing/egress-abuse possibilities even behind one shared password. Per-process in-memory rate limits do not synchronize across multiple instances or survive restarts.
- Docker outbound traffic requires further defense-in-depth: VPS firewall or infrastructure egress restrictions that cannot be bypassed by process-controlled DNS. Any additional host-wide restriction must account for other services on the server.
- The server is not a mail transfer agent and does not queue or track inbox delivery. SMTP acceptance means only that the receiving SMTP server returned a 2xx response.
- A shared password gives all authorized operators the same privileges; there is no per-user audit trail or individually revocable sessions.
- Server trust of proxy-forwarded IP data relies on NPM being correctly connected and sanitizing forwarding headers. Do not attach the container to an untrusted reverse proxy network or publish port 3000 directly.
- JavaScript/Node/OpenSSL, Docker base image, the proxy and the host OS must be maintained. Third-party dependencies are limited but not zero (container base image and CI actions).
- Continuous scanning, log shipping, formal penetration testing, audited egress, and security patches remain the deployer's responsibility.

## Responsible deployment

1. Use HTTPS and a strong unique access password; never reuse a technician's personal password.
2. Keep `ALLOW_SEND=0` by default. If enabled, use a narrowly scoped recipient list and review test-account permissions.
3. Pin production to a tested image tag or digest. Apply security updates deliberately.
4. Apply external inbound-rate limits at NPM/edge if appropriate. Use an external firewall or network egress policy suited to your overall host.
5. Do not commit `.env`, SMTP passwords, real message content, logs, credentials or cookies.
6. Treat test results and transcripts as potentially sensitive—even redacted output can contain domains, IP addresses, EHLO strings or email addresses.
7. Report a suspected vulnerability privately to the repository maintainer before public disclosure.
