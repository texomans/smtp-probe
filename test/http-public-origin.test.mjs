import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import net from 'node:net';

async function unusedPort() {
  return new Promise((resolve,reject)=>{
    const s=net.createServer();s.on('error',reject);
    s.listen(0,'127.0.0.1',()=>{const port=s.address().port;s.close(()=>resolve(port));});
  });
}
test('HTTPS proxy mode sets a __Host- Secure cookie and validates the configured origin',async t=>{
  const port=await unusedPort();
  const base=`http://127.0.0.1:${port}`;
  const publicOrigin='https://smtp.example.org';
  const password='Random-Only-Test-Secret-For-Proxy-123456';
  const processHandle=spawn(process.execPath,['src/server.mjs'],{
    cwd:process.cwd(),
    env:{...process.env,HOST:'127.0.0.1',PORT:String(port),SMTP_PROBE_PASSWORD:password,SMTP_PROBE_COOKIE_SECURE:'1',PUBLIC_ORIGIN:publicOrigin},
    stdio:['ignore','pipe','pipe'],
  });
  t.after(()=>{if(processHandle.exitCode===null)processHandle.kill('SIGTERM');});
  let ready=false;
  for(let i=0;i<70;i++) {
    if(processHandle.exitCode!==null) throw Error(`Unexpected startup exit ${processHandle.exitCode}`);
    try {const r=await fetch(`${base}/healthz`);if(r.ok){ready=true;break;}}catch{}
    await new Promise(resolve=>setTimeout(resolve,50));
  }
  assert.equal(ready,true);
  const payload=JSON.stringify({password});
  const badOrigin=await fetch(`${base}/api/login`,{method:'POST',headers:{'content-type':'application/json',origin:'https://evil.example',host:'smtp.example.org'},body:payload});
  assert.equal(badOrigin.status,403);
  const good=await fetch(`${base}/api/login`,{method:'POST',headers:{'content-type':'application/json',origin:publicOrigin,host:'smtp.example.org'},body:payload});
  assert.equal(good.status,200);
  const cookie=good.headers.get('set-cookie');
  assert.match(cookie,/__Host-smtp_probe_sid=/);
  assert.match(cookie,/; Secure/);
  assert.match(cookie,/; HttpOnly/);
  assert.match(cookie,/; SameSite=Strict/);
  assert.equal((await (await fetch(`${base}/api/info`,{headers:{cookie:cookie.split(';')[0]}})).json()).version,'0.2.0-beta.1');
});
