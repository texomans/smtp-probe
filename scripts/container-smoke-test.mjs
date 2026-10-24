import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

// Run inside the isolated candidate container; no SMTP traffic is generated.
const version = JSON.parse(readFileSync('package.json', 'utf8')).version;
const base = 'http://127.0.0.1:3000';
let healthy = false;
for (let attempt = 0; attempt < 100; attempt++) {
  try {
    const response = await fetch(`${base}/healthz`);
    assert.equal(response.status, 200);
    assert.equal((await response.json()).status, 'ok');
    healthy = true;
    break;
  } catch {
    await new Promise(resolve => setTimeout(resolve, 100));
  }
}
assert.ok(healthy, 'Candidate container did not become healthy');
assert.equal((await fetch(`${base}/api/info`)).status, 401);
assert.equal((await fetch(`${base}/api/dns-diagnostics`,{method:'POST'})).status,401);
assert.ok((await (await fetch(base)).text()).includes(`v${version}`));
const login = await fetch(`${base}/api/login`, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ password: process.env.SMTP_PROBE_PASSWORD }),
});
assert.equal(login.status, 200);
const { csrfToken } = await login.json();
const cookie = login.headers.get('set-cookie').split(';')[0];
const headers = { cookie, 'x-csrf-token': csrfToken };
const infoResponse = await fetch(`${base}/api/info`, { headers });
assert.equal(infoResponse.status, 200);
const info = await infoResponse.json();
assert.equal(info.version, version);
assert.equal(info.sendEnabled, false);
const dnsBody=JSON.stringify({fromDomain:'example.com'});
assert.equal((await fetch(`${base}/api/dns-diagnostics`,{method:'POST',headers:{cookie,'content-type':'application/json'},body:dnsBody})).status,403);
assert.equal((await fetch(`${base}/api/dns-diagnostics`,{method:'POST',headers:{...headers,'content-type':'application/json'},body:JSON.stringify({fromDomain:'127.0.0.1'})})).status,400);
const dnsResponse=await fetch(`${base}/api/dns-diagnostics`,{method:'POST',headers:{...headers,'content-type':'application/json'},body:dnsBody});
assert.equal(dnsResponse.status,200);
const dnsResult=await dnsResponse.json();
assert.equal(dnsResult.schemaVersion,1);
assert.equal(dnsResult.dkim.status,'not-tested');
assert.ok(dnsResult.scope.includes('No email sent'));
assert.ok(Array.isArray(dnsResult.queries));

assert.ok((await (await fetch(base, { headers })).text()).includes(`v${version}`));
assert.equal((await fetch(`${base}/api/logout`, { method: 'POST', headers })).status, 200);
assert.equal((await fetch(`${base}/api/info`, { headers })).status, 401);
console.log(`Container smoke test passed: v${version}; health, login/logout, page/API versions, sending disabled, DNS endpoint and access controls.`);
