import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
const text = path => readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');

test('default Compose pulls published image and listens only on loopback', () => {
  const compose = text('compose.yaml');
  assert.match(compose, /ghcr\.io\/texomans\/smtp-probe:v0\.2\.0-beta\.1/);
  assert.doesNotMatch(compose, /\bbuild:/);
  assert.match(compose, /127\.0\.0\.1:\$\{SMTP_PROBE_PORT:-3088\}:3000/);
  assert.match(compose, /SMTP_PROBE_COOKIE_SECURE: '0'/);
  assert.match(compose, /TRUST_PROXY: '0'/);
});
test('generic HTTPS Compose requires an existing network with no exposed ports', () => {
  const compose = text('compose.proxy.yaml');
  assert.match(compose, /SMTP_PROBE_PROXY_NETWORK:\?/);
  assert.match(compose, /PUBLIC_ORIGIN: \$\{PUBLIC_ORIGIN:\?/);
  assert.match(compose, /SMTP_PROBE_COOKIE_SECURE: '1'/);
  assert.match(compose, /TRUST_PROXY: '1'/);
  assert.match(compose, /external: true/);
  assert.doesNotMatch(compose, /^    ports:/m);
  assert.doesNotMatch(compose, /\bbuild:/);
  assert.doesNotMatch(compose, /NPM_NETWORK|nginx-proxy-manager/i);
});
test('staging is private and sending is forcibly off', () => {
  const compose = text('compose.staging.yaml');
  assert.match(compose, /127\.0\.0\.1:3090:3000/);
  assert.match(compose, /ALLOW_SEND: '0'/);
});
test('all Compose passwords use the current application prefix only', () => {
  for (const p of ['compose.yaml','compose.proxy.yaml','compose.staging.yaml','.env.example','src/server.mjs']) {
    assert.doesNotMatch(text(p), new RegExp('SMTP_' + 'SCOPE'));
  }
});
test('Docker, Komodo, Portainer and proxy installation guides exist', () => {
  for (const p of ['docs/DOCKER.md','docs/KOMODO.md','docs/PORTAINER.md','docs/REVERSE-PROXY.md']) {
    assert.ok(text(p).length > 200);
  }
});
test('GHCR tags publish multiarch images', () => {
  const ci = text('.github/workflows/publish-ghcr.yml');
  assert.match(ci, /linux\/amd64,linux\/arm64/);
  assert.match(ci, /packages: write/);
  assert.doesNotMatch(ci, /pull_request:/);
});
