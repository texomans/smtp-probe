#!/usr/bin/env node
// Passive public NPM gateway check: no password, SMTP credentials or test email.
const origin = process.argv[2] || 'https://smtpprobe.texomans.com';
let failures = 0;
if (!/^https:\/\/[^/]+$/.test(origin)) {
  console.error('Please pass an HTTPS origin with no trailing slash.');
  process.exit(2);
}
async function check(name, url, expectedStatus, opts = {}) {
  try {
    const res = await fetch(`${origin}${url}`, {redirect:'manual',cache:'no-store', ...opts});
    const success = res.status === expectedStatus;
    console.log(`${success?'PASS':'FAIL'} ${name}: HTTP ${res.status} (expected ${expectedStatus})`);
    if (!success) failures++;
    return res;
  } catch (e) {
    failures++;
    console.log(`FAIL ${name}: ${e.code || e.message}`);
    return null;
  }
}
const page = await check('HTTPS page loads', '/', 200);
const health = await check('Health endpoint', '/healthz', 200);
await check('Anonymous API info denied', '/api/info', 401);
await check('Anonymous API POST denied', '/api/test', 401, {
  method:'POST',headers:{'content-type':'application/json'},body:'{}',
});
const session = await check('Session status available', '/api/session', 200);
if (session?.ok) {
  const data = await session.json().catch(()=>({}));
  const success = data.authenticated === false;
  console.log(`${success?'PASS':'FAIL'} No session granted anonymously`);
  if (!success) failures++;
}
if (page) {
  for (const [name,header,match] of [
    ['No-cache header','cache-control',/no-store/i],
    ['Clickjacking protection','x-frame-options',/deny/i],
    ['Content security policy','content-security-policy',/default-src 'none'/i],
    ['HSTS (HTTPS only)','strict-transport-security',/max-age=/i],
  ]) {
    const success = match.test(page.headers.get(header) || '');
    console.log(`${success?'PASS':'FAIL'} ${name}`);
    if (!success) failures++;
  }
}
console.log(`\n${failures?'FAIL':'PASS'}: ${failures} gateway check(s) failed.`);
if (failures) process.exitCode = 1;
