# SMTP Probe

**Self-hosted, browser-based SMTP connectivity, authentication, TLS and delivery diagnostics.**

![Release](https://img.shields.io/badge/release-v0.2.0--beta.1-orange) ![License](https://img.shields.io/badge/license-MIT-blue)

**Status: public beta / development preview.** SMTP Probe is a real, functional SMTP diagnostic tool, but it has **not received an independent security audit**. Publishing an internet-facing instance requires an administrator to assess egress, credential-guessing, and abuse controls. **Actual email sending is disabled by default.**

SMTP Probe is an independently developed implementation inspired by the general SMTP-testing concept of [SMTPTester.org](https://smtptester.org). It is not affiliated with that project, and no code or site assets have been copied. Developed with AI assistance using OpenAI's ChatGPT—proudly *vibe-coded*. 😎

## What it does

- Opens real SMTP sessions and streams a redacted, step-by-step terminal-style transcript.
- Verifies the SMTP banner, EHLO extensions and server response codes.
- Performs STARTTLS or implicit TLS with certificate hostname and chain validation (TLS 1.2+).
- Authenticates using AUTH PLAIN, LOGIN or CRAM-MD5 over verified TLS.
- Optionally sends a **single test message** to one administratively approved recipient using supplied SMTP credentials, and records SMTP acceptance status. Delivery to an inbox must be verified separately.
- Exports a credential-redacted diagnostic report (including TLS details, capabilities, and submission receipt).
- Uses a single shared page password (no registration, account database, or third-party services).
- Has session expiration, secure cookies, CSRF enforcement, login throttling, per-client/host/account test limits, public-IP and port restrictions, and concurrency limits.
- Runs as a nonroot, read-only Docker container; no third-party Node.js runtime packages.

## Docker image

Once a Git tag is published via GitHub Actions, official multi-architecture images will be available under:

```text
ghcr.io/texomans/smtp-probe:v0.2.0-beta.1   # pinned public beta
ghcr.io/texomans/smtp-probe:beta              # moving beta tag for a home staging system
```

Images are built for **linux/amd64** and **linux/arm64**. GitHub Container Registry packages may initially be **private**; repository maintainers must make the image package public before anonymous pulls work. Until the workflow has published the image, these names are **planned image references, not live downloads**.

## Recommended: Komodo + Nginx Proxy Manager (or other TLS reverse proxy)

Use [compose.komodo.yaml](compose.komodo.yaml) as a **Komodo Stack** sourced from your GitHub repository. This file references a prebuilt GHCR image, publishes **no host ports**, and joins an **external Docker network** shared with your HTTPS reverse proxy.

Enter environment values in **Komodo → Stack → Environment** (not in the public repository). Minimal example:

```dotenv
SMTP_PROBE_PASSWORD='Use-A-Unique-Long-Memorable-Secret'
SMTP_PROBE_PASSWORD_MIN_LENGTH=15
PUBLIC_ORIGIN=https://smtp.example.com
NPM_NETWORK=proxied
SMTP_PROBE_IMAGE=ghcr.io/texomans/smtp-probe:v0.2.0-beta.1
ALLOW_SEND=0
SMTP_ALLOWED_HOSTS=
```

The password minimum defaults to **15** characters, but operators may set `SMTP_PROBE_PASSWORD_MIN_LENGTH` to any integer in **1–512**. Less than 15 is discouraged for internet-facing password-only access. Quote passwords with special characters in Compose-style `.env` input. Restart the container after changing the password to invalidate all sessions.

In NPM, create a Proxy Host for your domain forwarding to **`smtp-probe` port `3000` using HTTP**, with Let's Encrypt and Force SSL. Enable *Block Common Exploits*, and in Advanced settings use:

```nginx
proxy_buffering off;
proxy_read_timeout 75s;
proxy_send_timeout 75s;
```

See the [Komodo deployment and staging guide](docs/KOMODO.md) for a production/staging layout, expected checks, migration and rollback.

### Home-server staging

[compose.staging.yaml](compose.staging.yaml) pulls the current `:beta` image, forces `ALLOW_SEND=0`, and binds `127.0.0.1:3090`. Use an SSH tunnel to reach it while developing. Keep this separate from your VPS instance. It **does not** expose a plaintext password form on a LAN/public interface.

## SMTP policy settings

| Variable | Description |
| --- | --- |
| `SMTP_PROBE_PASSWORD` | Required, shared web-access password. Legacy `SMTP_SCOPE_PASSWORD` remains accepted. |
| `SMTP_PROBE_PASSWORD_MIN_LENGTH` | Default `15`; explicit range `1..512`. Legacy `SMTP_SCOPE_PASSWORD_MIN_LENGTH` accepted. |
| `SMTP_PROBE_COOKIE_SECURE` | Must be `1` for public HTTPS. The production stack sets it to `1`. |
| `PUBLIC_ORIGIN` | Exact `https://` origin; no trailing slash. Must match the browser hostname. |
| `NPM_NETWORK` | Existing external Docker network connected to NPM; often `proxied`. |
| `SMTP_PROBE_IMAGE` | Pin production to a tested GHCR tag; home staging may use `:beta`. |
| `SMTP_ALLOWED_HOSTS` | Empty = any **public** DNS SMTP hostname. Optional comma-separated exact hostnames. |
| `SMTP_SEND_ALLOWED_HOSTS` | Empty = any public SMTP hostname for sending (subject to the global host policy). |
| `SMTP_SEND_ALLOWED_RECIPIENTS` | Required **only if sending is enabled**. Comma-separated exact addresses or one wildcard in mailbox local part (e.g. `*@example.com`, `alerts+*@example.com`). `*@*` and wildcard domains are refused. |
| `ALLOW_SEND` | Default `0`. Set `1` only after reviewing outbound restrictions, authentication and recipient policy. |

Allowed destination ports are **25, 465, 587, 2525, 8465, and 443** by default (admin-configurable in Compose). IP literals and local/private/reserved destinations are rejected; DNS resolution is pinned to the verified public address. Browser auth is required even for read-only SMTP checks. Each send request supports exactly **one** recipient. The SMTP host input starts **blank**.

## Private/local development

```bash
cp .env.example .env
# Set your password in .env, and keep it out of Git.
docker compose up -d --build
curl -fsS http://127.0.0.1:3088/healthz
npm run check
npm test
```

Local Compose binds only to `127.0.0.1` and forces sending off. Open locally or via SSH tunnel. The minimum Node.js version for manual development is 22; the Dockerfile uses Node 24 Alpine. Test keys are generated locally by `npm test`; the source release excludes them.

## Security and limitations

- **Never** commit `.env`, credentials, real SMTP messages, or authentication cookies.
- **Do not** directly publish container port `3000`; use HTTPS through a reverse proxy and keep the password gate enabled.
- This beta has in-memory rate limits; clustered instances do not share counters. Additional VPS/Docker egress controls and independent threat review are recommended. See [SECURITY.md](docs/SECURITY.md).
- SMTP `250` means the server accepted responsibility for the message, **not** that it reached the inbox.
- OAuth2/XOAUTH2, SPF/DKIM/DMARC reporting, attachments, and saved profiles are not yet implemented.

## Publishing

See [RELEASE.md](docs/RELEASE.md) for the GitHub Actions GHCR publishing workflow, and [KOMODO.md](docs/KOMODO.md) for pulling by tag. The publishing workflow does **not** include any passwords or user SMTP credentials.

MIT license — [LICENSE](LICENSE). Copyright © 2026 SMTP Probe contributors.
