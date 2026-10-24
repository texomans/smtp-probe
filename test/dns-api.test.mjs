import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { createDnsHandler } from '../src/dns-api.mjs';
import { runDnsDiagnostics } from '../src/email-auth.mjs';
function setup(options={}) {
  let calls=0;
  const runner=options.run || (async input=>{calls++;return runDnsDiagnostics(input,{resolver:{async resolveTxt(){throw Object.assign(new Error(),{code:'ENODATA'});}}});});
  const handler=createDnsHandler({auth:{verifyCsrf:(_session,token)=>token==='valid'},checkOrigin:req=>req.headers.origin!=='https://evil.example',json:(res,status,body)=>{res.status=status;res.body=body;},readJsonBody:async req=>{if(req.badBody)throw new Error();return req.payload;},requesterIp:()=> '127.0.0.1',limiter:{allow:()=>options.allowed!==false},run:runner,maxActive:options.maxActive || 3});
  const request=(override={})=>({headers:{'content-type':'application/json','x-csrf-token':'valid',...override.headers},payload:override.payload || {fromDomain:'example.com'},badBody:override.badBody});
  const response=()=>Object.assign(new EventEmitter(),{destroyed:false,writableEnded:false});
  return {handler,request,response,calls:()=>calls};
}
test('DNS API enforces authentication, CSRF, origin, content type and validation before DNS',async()=>{
  const s=setup();
  for(const [options,session,expected] of [[{},null,401],[{headers:{'x-csrf-token':'bad'}},{},403],[{headers:{origin:'https://evil.example'}},{},403],[{headers:{'content-type':'text/plain'}},{},415],[{badBody:true},{},400],[{payload:{fromDomain:'127.0.0.1'}},{},400]]) {
    const res=s.response();await s.handler(s.request(options),res,session);assert.equal(res.status,expected);
  }
  assert.equal(s.calls(),0);
});
test('DNS API returns the engine result and never requests SMTP credentials',async()=>{
  const s=setup(),res=s.response();await s.handler(s.request(),res,{});
  assert.equal(res.status,200);assert.equal(res.body.input.fromDomain,'example.com');assert.equal(res.body.schemaVersion,1);
  assert.equal(res.body.dkim.status,'not-tested');assert.ok(res.body.scope.includes('No email sent'));assert.equal(s.calls(),1);
});
test('DNS API rate limit blocks the resolver work',async()=>{
  const s=setup({allowed:false}),res=s.response();await s.handler(s.request(),res,{});assert.equal(res.status,429);assert.equal(s.calls(),0);
});
test('DNS API limits concurrency and releases slots on completion',async()=>{
  let finish;
  const s=setup({maxActive:1,run:()=>new Promise(resolve=>{finish=resolve;})});
  const first=s.response();const pending=s.handler(s.request(),first,{});
  await new Promise(setImmediate);
  const second=s.response();await s.handler(s.request(),second,{});assert.equal(second.status,429);
  finish({ok:true});await pending;assert.equal(first.status,200);
  const third=s.response();const after=s.handler(s.request(),third,{});await new Promise(setImmediate);finish({ok:true});await after;assert.equal(third.status,200);
});
test('DNS API failure frees capacity without exposing exception details',async()=>{
  let fail=true;
  const s=setup({maxActive:1,run:async()=>{if(fail){fail=false;throw new Error('private exception');}return {ok:true};}});
  const first=s.response();await s.handler(s.request(),first,{});assert.equal(first.status,500);assert.ok(!JSON.stringify(first.body).includes('private'));
  const second=s.response();await s.handler(s.request(),second,{});assert.equal(second.status,200);
});
test('DNS API cancels outstanding work when the client disconnects',async()=>{
  let cancelled=false;
  const s=setup({run:(_input,{signal})=>new Promise(resolve=>signal.addEventListener('abort',()=>{cancelled=true;resolve({});},{once:true}))});
  const res=s.response(),pending=s.handler(s.request(),res,{});await new Promise(setImmediate);
  res.destroyed=true;res.emit('close');await pending;assert.equal(cancelled,true);assert.equal(res.status,undefined);assert.equal(res.listenerCount('close'),0);
});
