# Developer quickstart

Prerequisites: Node.js >=22; Docker for container builds. Node 24 is used in CI.

```bash
npm run check
npm test
```

`npm test` generates ephemeral TLS fixtures (ignored by Git), then exercises SMTP greeting/EHLO/STARTTLS, TLS certificates, AUTH, sending, safety checks, browser sessions, CSRF and rate limiting. The test suite uses synthetic credentials and local mock SMTP endpoints.

Run a private/local instance:

```bash
cp .env.example .env
# Set SMTP_PROBE_PASSWORD in the local .env; no passwords are shipped.
docker compose up -d --build
curl -fsS http://127.0.0.1:3088/healthz
```

The app uses the version in `package.json` for both `/api/info` and the HTML label. For new versions, update only that version and package/release docs; avoid hardcoded version labels in UI.

Do not commit artifacts containing private/test .env files. Prefer PRs with test coverage for networking changes.
