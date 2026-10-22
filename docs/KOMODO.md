# Deploy with Komodo (optional)

Komodo manages the **same prebuilt GHCR image** that normal Docker or Portainer users pull.

1. Create a **Stack** on your chosen Komodo Server. Repository: `https://github.com/texomans/smtp-probe`, branch `main`.
2. For private/SSH-tunnel access, choose `compose.yaml`. For public HTTPS behind any reverse proxy, choose `compose.proxy.yaml`.
3. Add variables in Komodo's Stack Environment/Secrets interface (do not commit passwords to GitHub). For HTTPS:

```dotenv
SMTP_PROBE_IMAGE=ghcr.io/texomans/smtp-probe:v0.2.0-beta.1
SMTP_PROBE_PASSWORD=your-unique-long-passphrase
SMTP_PROBE_PASSWORD_MIN_LENGTH=15
PUBLIC_ORIGIN=https://smtp.example.com
SMTP_PROBE_PROXY_NETWORK=your-existing-proxy-network
ALLOW_SEND=0
```

4. Use **Pull image** rather than Build image; deploy. In your reverse proxy, forward to `smtp-probe:3000` on that shared network (no host port mapping).
5. Check container health and login. See [reverse-proxy instructions](REVERSE-PROXY.md).

When entering variables into a manager GUI, follow that GUI's parsing rules; do not accidentally include quote characters in the password.

**For your VPS**, pin an explicitly tested version (or digest) and approve upgrades manually. **For private home-server staging**, use `compose.staging.yaml`, a different password and the moving `:beta` tag. Staging binds `127.0.0.1:3090` and always keeps sending disabled; access it using an SSH tunnel.

A `502` usually indicates a container startup error or an incorrect proxy network. Check container logs (without sharing credentials). Remember that the application refuses to start if the password does not meet the configured minimum.
