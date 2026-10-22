# Development

Use Node.js >=22 (CI uses 24). Tests generate temporary TLS fixtures and local mock SMTP servers:

```bash
npm run check
npm test
```

Run source directly with a **test-only** password:

```bash
SMTP_PROBE_PASSWORD='a-unique-long-test-passphrase' SMTP_PROBE_COOKIE_SECURE=0 ALLOW_SEND=0 HOST=127.0.0.1 node src/server.mjs
```

Or build a local image manually (regular `docker compose up -d` pulls a **published** image):

```bash
docker build -t smtp-probe:dev .
SMTP_PROBE_IMAGE=smtp-probe:dev docker compose up -d
```

The UI and API both read their version from `package.json`. Use separate test and production passwords. Never commit `.env`, TLS fixture private keys, SMTP credentials or client transcripts.
