# Deploy with Portainer (optional)

Portainer is one of several ways to manage the published SMTP Probe image; no Portainer-specific changes are required.

1. Open **Stacks → Add stack**, choose the **Repository** source and enter `https://github.com/texomans/smtp-probe`.
2. Set the Compose file path to `compose.yaml` for private use or `compose.proxy.yaml` for HTTPS behind your existing proxy.
3. Supply `SMTP_PROBE_PASSWORD` in Stack environment variables (15+ characters by default). Use Portainer secrets support when available.
4. For HTTPS, also supply `PUBLIC_ORIGIN=https://smtp.example.com` and `SMTP_PROBE_PROXY_NETWORK` pointing to the proxy's existing external network.
5. Deploy. The Stack pulls `ghcr.io/texomans/smtp-probe`; there is no local source build.
6. Confirm health and access at host loopback or your HTTPS hostname.

Do not accidentally make the private `3088` HTTP port public. Public proxy mode publishes **no host ports**. Keep `ALLOW_SEND=0` unless carefully authorizing recipients. See [reverse-proxy examples](REVERSE-PROXY.md).
