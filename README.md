# SMTP Probe

**Self-hosted browser-based SMTP connectivity, authentication, TLS inspection and test-message diagnostics.**

![License](https://img.shields.io/badge/license-MIT-blue) ![Status](https://img.shields.io/badge/status-public%20beta-orange)

**Public beta — not independently security-audited.** Actual email sending is disabled by default. SMTP Probe is independently developed, inspired by the general SMTP-testing concept of [SMTPTester.org](https://smtptester.org), without affiliation or copied code/assets. Developed with AI assistance using ChatGPT — proudly *vibe-coded*.

## Features

- Live, redacted SMTP transcripts with greeting, EHLO extensions and server replies
- STARTTLS and implicit TLS with certificate chain, hostname and cipher validation
- AUTH PLAIN, LOGIN and CRAM-MD5 over verified TLS
- Optional one-recipient test message with a server-enforced recipient allowlist
- Downloadable redacted reports and server acceptance receipts
- Shared web-access password, protected sessions, CSRF, login throttling and test rate limits
- Public-IP and SMTP-port restrictions; non-root, read-only container
- SPF, DKIM and DMARC DNS diagnostics with potential identifier alignment and copy/download reports
- No database, accounts, or third-party Node.js runtime packages

## Quick start — ordinary Docker Compose

**No Komodo, Portainer, or reverse proxy required** for a private install.

```bash
git clone https://github.com/texomans/smtp-probe.git
cd smtp-probe
cp .env.example .env
nano .env
docker compose pull
docker compose up -d
curl -fsS http://127.0.0.1:3088/healthz
```

Set `SMTP_PROBE_PASSWORD` in `.env` to a unique passphrase (default minimum **15 characters**). For Docker Compose `.env` syntax, single quotes safely preserve special characters such as `!` and `$`. Never commit `.env`.

Browse `http://127.0.0.1:3088` on the Docker host. For a remote server, use an SSH tunnel rather than opening a public HTTP port:

```bash
ssh -N -L 3088:127.0.0.1:3088 user@your-server
```

Then visit `http://127.0.0.1:3088` on your workstation.

The default [compose.yaml](compose.yaml) **pulls a prebuilt image**, `ghcr.io/texomans/smtp-probe:v0.2.0-beta.1`. It does not compile source. Select your approved release explicitly. Beta.4 DNS diagnostics require the beta.4 image once it is published. The Compose image is a fallback: set `SMTP_PROBE_IMAGE` explicitly to select the release you want.

Prefer raw `docker run`? See [Docker installation](docs/DOCKER.md).

## HTTPS behind your choice of reverse proxy

Use [compose.proxy.yaml](compose.proxy.yaml) and an existing external Docker network shared with your HTTPS proxy. It publishes **no host ports** and does not depend on any proxy vendor.

```dotenv
SMTP_PROBE_PASSWORD='your-unique-long-passphrase'
SMTP_PROBE_PASSWORD_MIN_LENGTH=15
PUBLIC_ORIGIN=https://smtp.example.com
SMTP_PROBE_PROXY_NETWORK=your-existing-proxy-network
SMTP_PROBE_IMAGE=ghcr.io/texomans/smtp-probe:v0.2.0-beta.1
ALLOW_SEND=0
```

```bash
docker compose -f compose.proxy.yaml up -d
```

Forward your HTTPS domain to `http://smtp-probe:3000` from the reverse proxy. See [Nginx Proxy Manager, Traefik, Caddy, and Nginx examples](docs/REVERSE-PROXY.md).

## Deployment guides

| Method | Instructions |
| --- | --- |
| Docker CLI / Docker Compose | [Docker](docs/DOCKER.md) |
| Komodo | [Komodo](docs/KOMODO.md) |
| Portainer | [Portainer](docs/PORTAINER.md) |
| Nginx Proxy Manager, Traefik, Caddy and Nginx | [Reverse proxies](docs/REVERSE-PROXY.md) |
| Development and staging | [Development](docs/DEVELOPMENT.md) |

## Configuration

| Environment variable | Behavior |
| --- | --- |
| `SMTP_PROBE_PASSWORD` | Required shared page password. |
| `SMTP_PROBE_PASSWORD_MIN_LENGTH` | Default `15`, configurable `1–512`; values below 15 discouraged for public access. |
| `SMTP_PROBE_IMAGE` | Published GHCR tag; pin a tested version. |
| `SMTP_PROBE_PORT` | Local/private port (default `3088`). |
| `PUBLIC_ORIGIN` | Full HTTPS origin without trailing slash. |
| `SMTP_PROBE_PROXY_NETWORK` | Existing external Docker network for HTTPS proxy mode. |
| `SMTP_ALLOWED_HOSTS` | Blank permits any public DNS SMTP hostname; optional exact-host list. |
| `SMTP_SEND_ALLOWED_HOSTS` | Optional send-only SMTP host restriction. |
| `SMTP_SEND_ALLOWED_RECIPIENTS` | Comma-separated exact recipients or mailbox patterns like `*@example.com`, never wildcard domains. |
| `ALLOW_SEND` | Off by default; opt-in requires authentication, verified TLS and an approved recipient. |

The SMTP hostname input starts **blank**. Each send attempt supports one recipient. SMTP `250 OK` does not establish inbox delivery.

Available images: [GHCR](https://github.com/texomans/smtp-probe/pkgs/container/smtp-probe), for `linux/amd64` and `linux/arm64`.

## Security and connectivity grading

Beta.3 adds a scorecard to completed SMTP tests and redacted report exports. Security and connectivity are separate: invalid credentials or rejected messages do not erase a validated TLS result. See [the grading policy](docs/GRADING.md) for rules, limitations and test scenarios.

## Email authentication DNS diagnostics

Use **SPF, DKIM & DMARC** below the SMTP workspace. Enter the visible From domain and optional MAIL FROM domain, DKIM signing domain and selectors. The tool inspects published DNS records; it does not send mail or verify actual message authentication. Copy/download exports are separate from SMTP reports. See [Email DNS diagnostics](docs/EMAIL-AUTH.md) for coverage, limits, DMARC discovery and live-test steps.

## Upcoming Features

We'll check these off as they're released:

- [x] **SPF, DKIM, and DMARC diagnostics** — Inspect DNS records, identify configuration issues, and report alignment.
- [ ] **HTML email testing** — Compose HTML messages with a plain-text alternative, safely preview the HTML, and test multipart email delivery.
- [ ] **OAuth2 / XOAUTH2 SMTP authentication** — Support modern authentication testing for providers such as Microsoft 365 and Google Workspace.
- [ ] **Saved SMTP profiles** — Reuse server, port, encryption, and other nonsecret connection settings without saving passwords by default.
- [ ] **Email attachments** — Send test messages with attachments under explicit file-size and type restrictions.
- [x] **SMTP security and connectivity grading** — Summarize TLS, certificate validation, supported authentication methods, and SMTP capabilities in an easy-to-read scorecard.

## Security

This beta's rate limits are in-memory and not a substitute for egress controls, edge protection or independent review. Read [SECURITY.md](docs/SECURITY.md) before publishing an instance. The software is released under the [MIT license](LICENSE).
