# SMTP Probe: Komodo deployments

The two intended environments are **a version-pinned VPS deployment** behind HTTPS and **a separate home-server staging deployment**. A Komodo *Stack* pulls the released image; Komodo should not compile the application on your server.

> **Before deployment:** the maintainer must publish the Git tag/image and set the GHCR package visibility to Public. Do not attempt to pull a non-existent image tag.

## A. VPS production-like beta (NPM on the same server)

1. In Komodo, create a new **Stack** named `smtp-probe` and select your VPS Server.
2. Select **Git repo** as the source, with repository `texomans/smtp-probe` on branch `main`. Set the Compose file path to `compose.komodo.yaml`.
3. Set the Stack project name to `smtp-probe` (no collision with old `smtp-scope`).
4. In the Stack **Environment**, configure the following. Use your own password, saved in your preferred secret store; never add it to source control:

```dotenv
SMTP_PROBE_IMAGE=ghcr.io/texomans/smtp-probe:v0.2.0-beta.1
SMTP_PROBE_PASSWORD='Replace-With-Your-Unique-Long-Password'
SMTP_PROBE_PASSWORD_MIN_LENGTH=15
PUBLIC_ORIGIN=https://smtpprobe.texomans.com
NPM_NETWORK=proxied
ALLOW_SEND=0
SMTP_ALLOWED_HOSTS=
SMTP_SEND_ALLOWED_HOSTS=
SMTP_SEND_ALLOWED_RECIPIENTS=
```

5. Keep **Run build** disabled and use **Pull image before deploy** (or equivalent Auto Pull option). Disable automatic updating for production; pinning to a specific tested image prevents surprise changes. Choose *Deploy*.
6. Confirm container `smtp-probe` is healthy and on Docker network `proxied`, with **no host-published port**. You can verify on the VPS:

```bash
docker inspect smtp-probe --format '{{json .NetworkSettings.Networks}}'
docker port smtp-probe
docker exec smtp-probe node -e "fetch('http://127.0.0.1:3000/healthz').then(async r=>console.log(r.status,await r.text()))"
```

7. In NPM, create a **new** Proxy Host for `smtpprobe.texomans.com`: `http://smtp-probe:3000`. Enable Let's Encrypt and Force SSL. Optionally use the Advanced settings below for streamed transcript events:

```nginx
proxy_buffering off;
proxy_read_timeout 75s;
proxy_send_timeout 75s;
```

8. Ensure the DNS record for the new hostname points to the VPS running NPM. Verify authentication and SSE over HTTPS. No firewall or externally mapped SMTP Probe ports are needed.
9. Run the included read-only gateway check from an Internet-capable host:

```bash
python3 scripts/public-proxy-check.py https://smtpprobe.texomans.com
python3 scripts/https-auth-smoke-test.py https://smtpprobe.texomans.com
```

Both checks should end with zero failures. The second asks for your web-access password **without echoing it**. Then confirm a real verify-only SMTP connection from the browser (e.g. `mail.smtp2go.com`, port 587, STARTTLS, no credentials).

### Policy and upgrade philosophy

- **Production/VPS:** use `SMTP_PROBE_IMAGE=ghcr.io/texomans/smtp-probe:v0.2.0-beta.1` and update it deliberately only after staging passes.
- **Home/staging:** use `ghcr.io/texomans/smtp-probe:beta` (moving beta tag). Komodo's image-update indicator can check for a newer digest without redeploying automatically.
- Keep `ALLOW_SEND=0` in both until you intentionally need a test send. Real credentials should never go in Compose environment or GitHub.
- Rebuilding SMTP Probe in Komodo is unnecessary; the image is built on GitHub-hosted CI, and Komodo pulls it.

## B. Home-server staging (private/loopback)

1. Create a second Komodo Stack named `smtp-probe-staging` on your home Server.
2. Select `compose.staging.yaml` from the same Git repository, using a distinct project name.
3. Supply a **different** `SMTP_PROBE_PASSWORD` from the VPS password, plus `SMTP_PROBE_PASSWORD_MIN_LENGTH=15` and `SMTP_PROBE_IMAGE=ghcr.io/texomans/smtp-probe:beta`.
4. Deploy. The service binds **only to 127.0.0.1:3090 on the home server**, never the LAN IP or public interface. The staging Compose forces `ALLOW_SEND=0`.
5. From your workstation, open an SSH tunnel (replace host/login accordingly):

```bash
ssh -N -L 3090:127.0.0.1:3090 <HOME_SSH_USER>@<HOME_SERVER_ADDRESS>
```

Then open `http://127.0.0.1:3090` on that workstation. The staging cookie may be non-Secure because this connection is protected by SSH and is local-only; **do not publish that HTTP port**.

## C. Migrating from SMTP Scope

The old project is a separate Compose project called `smtp-scope`. The new stack uses `smtp-probe` and the **new hostname**, so they can coexist during cutover.

1. Preserve the old `/opt/smtp-scope/.env` and backup the old Compose directory locally. **Do not copy `.env` into GitHub**.
2. Publish the new image, deploy `smtp-probe` in Komodo, and configure the new hostname/SSL while leaving the old site online.
3. Move your password policy settings into the new Komodo Stack environment. `SMTP_SCOPE_PASSWORD` and `SMTP_SCOPE_PASSWORD_MIN_LENGTH` still work if you prefer to use the old names temporarily. `SMTP_PROBE_PASSWORD` takes priority when both are set. Sessions from the old hostname do not migrate; logging in again is expected.
4. Complete HTTPS, authentication, certificate and SMTP verify checks for `smtpprobe.texomans.com`.
5. Only **after** the new site is verified, retire the old NPM Proxy Host and then retire the old app:

```bash
cd /opt/smtp-scope
docker compose -f compose.npm.example.yaml down
```

Use the `sudo` prefix if you normally run Docker with sudo. This targets only the *old* manual Compose project. Do not remove your `proxied` Docker network—NPM and other services use it. Never run `docker compose down` without confirming the Compose file and working directory.

6. Keep the old archive as a short-term rollback option until the new deployment proves reliable. To roll back, restore the prior Compose app and old NPM Proxy Host; switch DNS or use the older hostname as appropriate.

## Common problems

| Symptom | Likely cause / check |
| --- | --- |
| `502 Bad Gateway` from NPM | App not healthy, password below configured minimum, invalid recipient policy, or wrong network/hostname; inspect `docker logs smtp-probe`. |
| Cannot pull `ghcr.io` image | Image not published, wrong tag, or GHCR package still private. |
| Login succeeds but tests fail (403) | `PUBLIC_ORIGIN` doesn't match HTTPS hostname or CSRF is missing; log out and log in again after fixing. |
| No streaming events | In NPM Advanced, set `proxy_buffering off;` and ~75s proxy read timeout. |
| Browser SSL cookie doesn't stick | `SMTP_PROBE_COOKIE_SECURE=1`, valid HTTPS, and correct reverse-proxy hostname are required. |
| Can't access home staging from LAN | Intentional—port 3090 is loopback-only. Use the SSH tunnel. |
