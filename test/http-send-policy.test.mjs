import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import net from 'node:net';

const PASSWORD = 'only-a-test-password-never-used-in-production-123';
async function unusedPort() {
  return await new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      server.close(() => resolve(port));
    });
  });
}
async function startServer(t, values) {
  const port = await unusedPort();
  const base = `http://127.0.0.1:${port}`;
  const child = spawn(process.execPath, ['src/server.mjs'], {
    cwd: process.cwd(),
    env: {
      ...process.env, HOST: '127.0.0.1', PORT: String(port),
      SMTP_PROBE_PASSWORD: PASSWORD, SMTP_PROBE_COOKIE_SECURE: '0', PUBLIC_ORIGIN: '',
      ...values,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  t.after(() => {if (child.exitCode === null) child.kill('SIGTERM');});
  let ready = false;
  for (let i = 0; i < 80; i++) {
    if (child.exitCode !== null) throw Error(`Application exited during startup: ${child.exitCode}`);
    try { if ((await fetch(`${base}/healthz`)).ok) { ready = true; break; } } catch {}
    await new Promise(r => setTimeout(r, 30));
  }
  assert.equal(ready, true, 'App should start successfully');
  return base;
}

test('Public-facing send opt-in rejects unauthorized requests and non-approved recipients/hosts', async t => {
  const base = await startServer(t, {
    ALLOW_SEND: '1',
    SMTP_SEND_ALLOWED_HOSTS: 'mail.smtp2go.com',
    SMTP_SEND_ALLOWED_RECIPIENTS: 'authorized@example.com',
  });
  const payload = {
    host: 'mail.smtp2go.com', port: 587, tlsMode: 'starttls', mode: 'send',
    username: 'tester', password: 'test-credential', authMethod: 'auto',
    from: 'from@example.com', to: 'not-authorized@example.com', subject: 'Test', message: 'Test content',
  };
  const anonymous = await fetch(`${base}/api/test`, {method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify(payload)});
  assert.equal(anonymous.status, 401);
  const login = await fetch(`${base}/api/login`, {method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify({password:PASSWORD})});
  assert.equal(login.status, 200);
  const details = await login.json();
  const cookie = login.headers.get('set-cookie').split(';')[0];
  const info = await fetch(`${base}/api/info`, {headers:{cookie}});
  assert.equal((await info.json()).sendEnabled, true);
  const missingCsrf = await fetch(`${base}/api/test`, {method:'POST', headers:{cookie,'content-type':'application/json'},body:JSON.stringify(payload)});
  assert.equal(missingCsrf.status, 403);
  const headers = {cookie,'content-type':'application/json','x-csrf-token':details.csrfToken};
  const disallowedRecipient = await fetch(`${base}/api/test`, {method:'POST',headers,body:JSON.stringify(payload)});
  assert.equal(disallowedRecipient.status, 400);
  assert.match((await disallowedRecipient.json()).error,/recipient is not permitted/);
  const disallowedHost = await fetch(`${base}/api/test`, {method:'POST',headers,body:JSON.stringify({...payload,to:'authorized@example.com',host:'smtp.notauthorized.com'})});
  assert.equal(disallowedHost.status, 400);
  assert.match((await disallowedHost.json()).error,/SMTP host is not permitted/);
});

test('Setting ALLOW_SEND=1 without approved recipients refuses application startup', async () => {
  const child = spawn(process.execPath, ['src/server.mjs'], {
    cwd:process.cwd(),
    env:{...process.env, PORT:'0',SMTP_PROBE_PASSWORD:PASSWORD,ALLOW_SEND:'1',SMTP_SEND_ALLOWED_HOSTS:'',SMTP_SEND_ALLOWED_RECIPIENTS:''},
    stdio:['ignore','pipe','pipe'],
  });
  let stderr = '';
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', chunk => {stderr += chunk;});
  const code = await new Promise(resolve => child.on('exit', resolve));
  assert.notEqual(code,0);
  assert.match(stderr,/requires a nonempty SMTP_SEND_ALLOWED_RECIPIENTS/);
});


test('Public HTTP send endpoint enforces recipient wildcard without requiring host restriction', async t => {
  const base = await startServer(t, {
    ALLOW_SEND:'1',SMTP_SEND_ALLOWED_HOSTS:'',
    SMTP_SEND_ALLOWED_RECIPIENTS:'*@example.org, person@example.com',
  });
  const login = await fetch(`${base}/api/login`, {method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({password:PASSWORD})});
  assert.equal(login.status,200);
  const body = await login.json();
  const headers = {cookie:login.headers.get('set-cookie').split(';')[0],
    'x-csrf-token':body.csrfToken, 'content-type':'application/json'};
  const payload = { host:'smtp.office365.com',port:587,tlsMode:'starttls',mode:'send',
    username:'someuser',password:'somepass',from:'from@example.com',
    to:'user@other.example',subject:'Test',message:'Test content'};
  const forbidden = await fetch(`${base}/api/test`,{method:'POST',headers,body:JSON.stringify(payload)});
  assert.equal(forbidden.status,400);
  assert.match((await forbidden.json()).error,/recipient is not permitted/);
  const forbiddenSubdomain = await fetch(`${base}/api/test`,{method:'POST',headers,
    body:JSON.stringify({...payload,to:'somebody@sub.example.org'})});
  assert.equal(forbiddenSubdomain.status,400);
  assert.match((await forbiddenSubdomain.json()).error,/recipient is not permitted/);
});
