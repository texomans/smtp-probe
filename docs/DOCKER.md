# Install with Docker (no manager required)

## Docker Compose

```bash
git clone https://github.com/texomans/smtp-probe.git
cd smtp-probe
cp .env.example .env
nano .env
docker compose pull
docker compose up -d
docker compose ps
curl -fsS http://127.0.0.1:3088/healthz
```

In `.env`, set `SMTP_PROBE_PASSWORD` to a unique passphrase at least 15 characters long (unless you've deliberately changed the policy). The default Compose file pulls a published image and binds **127.0.0.1:3088 only**.

Open `http://127.0.0.1:3088` on the host, or create an **SSH tunnel** from your workstation:

```bash
ssh -N -L 3088:127.0.0.1:3088 user@docker-server
```

## Docker CLI (without Compose)

Make a private `probe.env` with:

```dotenv
SMTP_PROBE_PASSWORD=your-long-unique-secret
SMTP_PROBE_PASSWORD_MIN_LENGTH=15
SMTP_PROBE_COOKIE_SECURE=0
TRUST_PROXY=0
ALLOW_SEND=0
```

```bash
chmod 600 probe.env
docker pull ghcr.io/texomans/smtp-probe:v0.2.0-beta.1
docker run -d --name smtp-probe --restart unless-stopped \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit 100 --memory 256m --cpus 1 \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  -p 127.0.0.1:3088:3000 --env-file ./probe.env \
  ghcr.io/texomans/smtp-probe:v0.2.0-beta.1
```

**Important:** Docker `run --env-file` reads values literally. Put the password **without surrounding quotes** in `probe.env` even if it contains special characters. Compose `.env` syntax, by contrast, supports surrounding single quotes. Do not put credentials directly into command arguments.

## Updating and HTTPS

```bash
docker compose pull
docker compose up -d
docker compose logs --tail=80
```

For HTTPS, use [compose.proxy.yaml](../compose.proxy.yaml) with [your chosen proxy](REVERSE-PROXY.md). Do **not** change the private HTTP binding to `0.0.0.0`.
