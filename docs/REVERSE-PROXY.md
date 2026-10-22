# Optional HTTPS reverse-proxy configuration

SMTP Probe works behind **Nginx Proxy Manager, Traefik, Caddy, ordinary Nginx**, or another trusted proxy. None is required by the software.

## Common container-network setup

1. Create or reuse an external Docker bridge network, e.g. `docker network create smtp-web`. Ensure your existing proxy is also attached to it.
2. Set `SMTP_PROBE_PASSWORD` and these values in the Compose environment:

```dotenv
PUBLIC_ORIGIN=https://smtp.example.com
SMTP_PROBE_PROXY_NETWORK=smtp-web
ALLOW_SEND=0
```

3. Start `docker compose -f compose.proxy.yaml up -d`.
4. Point the HTTPS proxy to **`http://smtp-probe:3000`**. The application publishes no host ports. Configure a valid TLS certificate and HTTPS-only access.

Streaming SMTP transcripts use **Server-Sent Events**. Avoid proxy buffering and allow requests lasting about 75 seconds. Only attach SMTP Probe to a **trusted** proxy network. Strip or overwrite untrusted client-supplied forwarding headers.

## Nginx Proxy Manager

Create a Proxy Host for `smtp.example.com`, scheme `http`, forward hostname `smtp-probe`, port `3000`. Request a Let's Encrypt certificate and enable Force SSL.

Add in the Advanced tab:

```nginx
proxy_buffering off;
proxy_read_timeout 75s;
proxy_send_timeout 75s;
```

Attach the NPM container to the same external Docker network.

## Caddy

With Caddy attached to that Docker network, this Caddyfile allows automatic HTTPS:

```caddyfile
smtp.example.com {
    reverse_proxy smtp-probe:3000 {
        flush_interval -1
    }
}
```

## Traefik

With Traefik's Docker provider, use an **optional Compose override** with these labels, or equivalent file-provider configuration:

```yaml
services:
  app:
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.smtp-probe.rule=Host(`smtp.example.com`)"
      - "traefik.http.routers.smtp-probe.entrypoints=websecure"
      - "traefik.http.routers.smtp-probe.tls.certresolver=letsencrypt"
      - "traefik.http.services.smtp-probe.loadbalancer.server.port=3000"
```

Use your existing entrypoint and certificate resolver names; your proxy and app must share the Docker network. If the container joins multiple networks, specify the correct network using `traefik.docker.network`.

## Ordinary Nginx

Within an existing TLS-enabled Nginx virtual host able to resolve `smtp-probe` on the shared network:

```nginx
location / {
    proxy_pass http://smtp-probe:3000;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_buffering off;
    proxy_read_timeout 75s;
}
```

Proxy TLS setup, certificate renewals and redirects remain administrator responsibilities.

## Verify

```bash
python3 scripts/public-proxy-check.py https://smtp.example.com
python3 scripts/https-auth-smoke-test.py https://smtp.example.com
```

Both should pass. Test live SMTP verification through the web UI. Leave `ALLOW_SEND=0` until intentionally configuring approved recipients. For a proxy running outside Docker, arrange a private upstream route rather than publicly exposing port 3000.
