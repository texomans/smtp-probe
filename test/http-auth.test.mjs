import test from 'node:test';
import { readFileSync } from 'node:fs';
const EXPECTED_VERSION = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version;
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import net from 'node:net';
import { once } from 'node:events';

const PASSWORD = 'a-Very-Long-Test-Only-Access-Secret-123456789';
async function unusedPort() {
  return new Promise((resolve,reject) => {
    const server=net.createServer();
    server.once('error',reject);
    server.listen(0,'127.0.0.1',()=>{
      const port=server.address().port;
      server.close(()=>resolve(port));
    });
  });
}
async function waitUntilHealthy(base, child) {
  for(let i=0;i<70;i++) {
    if(child.exitCode!==null) throw new Error(`Application exited early: ${child.exitCode}`);
    try {const response=await fetch(`${base}/healthz`);if(response.ok) return;}catch{}
    await new Promise(resolve=>setTimeout(resolve,50));
  }
  throw new Error('Application did not start within 3.5s.');
}

test('HTTP endpoints require session authentication plus CSRF; logout revokes access', async t => {
  const port=await unusedPort();
  const base=`http://127.0.0.1:${port}`;
  const child=spawn(process.execPath,['src/server.mjs'],{
    cwd:process.cwd(),
    env:{...process.env,HOST:'127.0.0.1',PORT:String(port),SMTP_PROBE_PASSWORD:PASSWORD,SMTP_PROBE_PASSWORD_MIN_LENGTH:'15',SMTP_PROBE_COOKIE_SECURE:'0',ALLOW_SEND:'0',PUBLIC_ORIGIN:''},
    stdio:['ignore','pipe','pipe'],
  });
  t.after(()=>{if(child.exitCode===null) child.kill('SIGTERM');});
  let stdout='';
  child.stdout.on('data',chunk=>{stdout+=chunk.toString('utf8');});
  await waitUntilHealthy(base,child);
  assert.ok(stdout.includes(`SMTP Probe v${EXPECTED_VERSION} listening on 127.0.0.1:${port} (send enabled: false)`),stdout);
  const noAuth=await fetch(`${base}/api/test`,{method:'POST',headers:{'content-type':'application/json'},body:'{}'});
  assert.equal(noAuth.status,401);
  const noInfo=await fetch(`${base}/api/info`);
  assert.equal(noInfo.status,401);
  const noCode=await fetch(`${base}/app.js`);
  assert.equal(noCode.status,401);
  const loginPage=await (await fetch(base)).text();
  assert.match(loginPage,/Unlock diagnostics/);
  const negative=await fetch(`${base}/api/login`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({password:'wrong'})});
  assert.equal(negative.status,401);
  const outside=await fetch(`${base}/api/login`,{method:'POST',headers:{'content-type':'application/json',origin:'https://evil.example'},body:JSON.stringify({password:PASSWORD})});
  assert.equal(outside.status,403);
  const accepted=await fetch(`${base}/api/login`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({password:PASSWORD})});
  assert.equal(accepted.status,200);
  const details=await accepted.json();
  const cookie=accepted.headers.get('set-cookie').split(';')[0];
  assert.ok(details.csrfToken);
  assert.ok(!cookie.includes(PASSWORD));
  const session=await (await fetch(`${base}/api/session`,{headers:{cookie}})).json();
  assert.equal(session.authenticated,true);
  assert.equal(session.csrfToken,details.csrfToken);
  const livePage=await (await fetch(base,{headers:{cookie}})).text();
  assert.match(livePage,/See the/);
  const info=await (await fetch(`${base}/api/info`,{headers:{cookie}})).json();
  assert.equal(info.version,EXPECTED_VERSION);
  assert.equal(info.name,'SMTP Probe');
  assert.ok(loginPage.includes('v' + EXPECTED_VERSION));
  assert.ok(livePage.includes('v' + EXPECTED_VERSION));
  assert.doesNotMatch(loginPage,/__SMTP_PROBE_VERSION__/);
  assert.equal(info.sendEnabled,false);
  const missingCsrf=await fetch(`${base}/api/test`,{method:'POST',headers:{cookie,'content-type':'application/json'},body:'{}'});
  assert.equal(missingCsrf.status,403);
  const invalidBody=await fetch(`${base}/api/test`,{method:'POST',headers:{cookie,'content-type':'application/json','x-csrf-token':details.csrfToken},body:'{}'});
  assert.equal(invalidBody.status,400);
  const badLogout=await fetch(`${base}/api/logout`,{method:'POST',headers:{cookie}});
  assert.equal(badLogout.status,403);
  const okLogout=await fetch(`${base}/api/logout`,{method:'POST',headers:{cookie,'x-csrf-token':details.csrfToken}});
  assert.equal(okLogout.status,200);
  assert.match(okLogout.headers.get('set-cookie'),/Max-Age=0/);
  assert.equal((await (await fetch(`${base}/api/session`,{headers:{cookie}})).json()).authenticated,false);
  assert.equal((await fetch(`${base}/api/info`,{headers:{cookie}})).status,401);
});


test('SMTP_PROBE_PASSWORD_MIN_LENGTH is respected by the running HTTP server', async t => {
  const port=await unusedPort();
  const base=`http://127.0.0.1:${port}`;
  const password='MyPassphrase!'; // 13 characters
  const child=spawn(process.execPath,['src/server.mjs'],{
    cwd:process.cwd(),
    env:{...process.env,HOST:'127.0.0.1',PORT:String(port),SMTP_PROBE_PASSWORD:password,
      SMTP_PROBE_PASSWORD_MIN_LENGTH:'12',SMTP_PROBE_COOKIE_SECURE:'0',ALLOW_SEND:'0',PUBLIC_ORIGIN:''},
    stdio:['ignore','pipe','pipe'],
  });
  t.after(()=>{if(child.exitCode===null) child.kill('SIGTERM');});
  await waitUntilHealthy(base,child);
  const response=await fetch(`${base}/api/login`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({password})});
  assert.equal(response.status,200);
  assert.equal((await response.json()).ok,true);
});

test('Misconfigured minimum or too-short secret fail startup with actionable, non-secret errors', async () => {
  async function expectError(minimum, password, expected) {
    const child=spawn(process.execPath,['src/server.mjs'],{
      cwd:process.cwd(),
      env:{...process.env,HOST:'127.0.0.1',PORT:'0',SMTP_PROBE_PASSWORD:password,
        SMTP_PROBE_PASSWORD_MIN_LENGTH:minimum,ALLOW_SEND:'0',PUBLIC_ORIGIN:'',SMTP_PROBE_COOKIE_SECURE:'0'},
      stdio:['ignore','pipe','pipe'],
    });
    let stderr='';
    child.stderr.on('data',chunk=>{stderr+=chunk.toString('utf8');});
    const code=await Promise.race([
      once(child,'exit').then(([status])=>status),
      new Promise((_,reject)=>setTimeout(()=>reject(new Error('Server failed to exit after invalid configuration')),2000)),
    ]).finally(()=>{if(child.exitCode===null)child.kill('SIGTERM');});
    assert.notEqual(code,0);
    assert.match(stderr,expected);
    assert.doesNotMatch(stderr,/MyPassphrase!/);
  }
  await expectError('15','MyPassphrase!',/SMTP_PROBE_PASSWORD.*between 15 and 512/);
  await expectError('0','a-long-enough-access-passphrase',/SMTP_PROBE_PASSWORD_MIN_LENGTH.*whole number/);
});
