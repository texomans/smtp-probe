import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
const text = path => readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');

test('Komodo Compose pulls version-pinned GHCR image with no host-published ports', () => {
  const prod = text('compose.komodo.yaml');
  assert.match(prod, /ghcr\.io\/texomans\/smtp-probe:v0\.2\.0-beta\.1/);
  assert.doesNotMatch(prod, /\bbuild:/);
  assert.doesNotMatch(prod, /^    ports:/m);
  assert.match(prod, /ALLOW_SEND: \${ALLOW_SEND:-0}/);
  assert.match(prod, /external: true/);
});

test('Staging only binds loopback and does not enable sends', () => {
  const staging = text('compose.staging.yaml');
  assert.match(staging, /127\.0\.0\.1:3090:3000/);
  assert.match(staging, /ALLOW_SEND: '0'/);
});

test('GHCR release builds both standard server architectures, without pushing on PRs', () => {
  const ci = text('.github/workflows/publish-ghcr.yml');
  assert.match(ci, /linux\/amd64,linux\/arm64/);
  assert.match(ci, /tags:/);
  assert.match(ci, /packages: write/);
  assert.doesNotMatch(ci, /pull_request:/);
});
