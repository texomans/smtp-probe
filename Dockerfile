FROM node:24-alpine
LABEL org.opencontainers.image.title="SMTP Probe" \
      org.opencontainers.image.description="Self-hosted SMTP verification and TLS diagnostics" \
      org.opencontainers.image.source="https://github.com/texomans/smtp-probe" \
      org.opencontainers.image.licenses="MIT"
WORKDIR /app
COPY package.json ./
COPY src ./src
COPY public ./public
ENV NODE_ENV=production PORT=3000 HOST=0.0.0.0 ALLOW_SEND=0 TRUST_PROXY=0 SMTP_PROBE_COOKIE_SECURE=1
USER node
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD node -e "fetch('http://127.0.0.1:3000/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "src/server.mjs"]
