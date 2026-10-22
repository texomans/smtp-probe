import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';

const html = readFileSync(new URL('../public/index.html', import.meta.url), 'utf8');
const js = readFileSync(new URL('../public/app.js', import.meta.url), 'utf8');

test('SMTP hostname starts blank and does not prefill a service', () => {
  const element = html.match(/<input\s+id=\"host\"[^>]*>/)?.[0];
  assert.ok(element, 'SMTP hostname input must exist');
  assert.doesNotMatch(element, /\svalue\s*=/, 'SMTP hostname must not have a preset value');
  assert.doesNotMatch(element, /smtp2go/i, 'SMTP2GO must not be the hostname placeholder');
  assert.match(js, /addEventListener\('pageshow',.*?\$\('host'\)\.value\s*=\s*''/, 'hostname must be cleared on reload and history restoration');
});

test('Both page version labels come from the server, not stale HTML literals', () => {
  const login = readFileSync(new URL('../public/login.html', import.meta.url), 'utf8');
  for (const page of [html, login]) {
    assert.match(page, /v__SMTP_PROBE_VERSION__/);
    assert.doesNotMatch(page, /<span class="version">v[0-9]/);
  }
});
