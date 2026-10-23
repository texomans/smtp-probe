import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const { version } = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
const script = fileURLToPath(new URL('../scripts/check-release-version.mjs', import.meta.url));
const check = (...args) => spawnSync(process.execPath, [script, ...args], { encoding: 'utf8' });

test('release gate accepts the exact package version tag', () => {
  const result = check(`v${version}`);
  assert.equal(result.status, 0, result.stderr);
  assert.ok(result.stdout.includes(`v${version}`));
});

test('release gate rejects missing, stale and malformed tags before publication', () => {
  for (const args of [[], ['v0.0.0'], [version], [`v${version}-extra`]]) {
    const result = check(...args);
    assert.equal(result.status, 1, result.stdout);
    assert.ok(result.stderr.includes(`expected v${version}`));
  }
});
