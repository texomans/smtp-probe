import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { validateDnsInput, normalizeDomain, parseSpf, parseDmarc, parseDkim, runDnsDiagnostics } from '../src/email-auth.mjs';
const rr = text => [[text]];
const policy='v=DMARC1; p=reject; psd=n; rua=mailto:reports@example.com';
function resolverFor(records={}) {
  const calls=[];
  return {calls, async resolveTxt(name) {
    calls.push(name);
    if (!(name in records)) throw Object.assign(new Error('not present'),{code:'ENODATA'});
    const answer=records[name];
    if (answer instanceof Error) throw answer;
    if (typeof answer==='function') return answer();
    return typeof answer==='string' ? rr(answer) : answer;
  }};
}
const run=(input={}, records={}, options={})=>runDnsDiagnostics({fromDomain:'example.com',...input},{resolver:resolverFor(records),...options});
const has=(value,text)=>JSON.stringify(value).includes(text);
const rsaRecord=bits=>`v=DKIM1; k=rsa; p=${generateKeyPairSync('rsa',{modulusLength:bits}).publicKey.export({format:'der',type:'spki'}).toString('base64')}`;
const rsa2048=rsaRecord(2048),rsa1024=rsaRecord(1024);

test('DNS inputs normalize IDNs and trailing dots; selectors are explicit and bounded',()=>{
  assert.equal(normalizeDomain('BÜCHER.de.'),'xn--bcher-kva.de');
  assert.deepEqual(validateDnsInput({fromDomain:'EXAMPLE.COM',selectors:'selector1, selector2, selector1'}).selectors,['selector1','selector2']);
  for(const fromDomain of ['127.0.0.1','http://example.com','a@example.com','example.com/a','x.local','x.internal','x.arpa','x.test','localhost','example.com\n','-bad.example.com']) assert.throws(()=>validateDnsInput({fromDomain}));
  for(const selectors of ['a,b,c,d,e','bad selector','a.b',[], 'a'.repeat(64)]) assert.throws(()=>validateDnsInput({fromDomain:'example.com',selectors}));
  assert.throws(()=>validateDnsInput({fromDomain:'example.com',dkimDomain:'http://example.com'}));
});
test('SPF split TXT chunks stay one record while multiple RRs are an error',async()=>{
  const one=await run({}, {'example.com':[['v=spf1 ','ip4:192.0.2.0/24 -all']]});
  assert.equal(one.spf.status,'ok');assert.equal(one.spf.nodes[0].records.length,1);
  const two=await run({}, {'example.com':[['v=spf1 -all'],['v=spf1 ~all']]});
  assert.equal(two.spf.status,'error');assert.ok(has(two.spf,'Multiple SPF records'));
});
test('SPF follows nested includes and redirects and caches repeated queries',async()=>{
  const resolver=resolverFor({'example.com':'v=spf1 include:provider.example.com include:provider.example.com -all','provider.example.com':'v=spf1 redirect=final.example.com','final.example.com':'v=spf1 ip4:192.0.2.1 -all'});
  const result=await runDnsDiagnostics({fromDomain:'example.com'},{resolver});
  assert.equal(result.spf.status,'ok');assert.equal(result.spf.lookupTerms,4);
  assert.equal(resolver.calls.filter(x=>x==='provider.example.com').length,1);
  assert.equal(resolver.calls.filter(x=>x==='final.example.com').length,1);
});
test('SPF cycles and missing include records are diagnosed',async()=>{
  const cycle=await run({}, {'example.com':'v=spf1 include:loop.example.com -all','loop.example.com':'v=spf1 include:example.com -all'});
  assert.ok(has(cycle.spf,'cycle'));assert.equal(cycle.spf.status,'error');
  const missing=await run({}, {'example.com':'v=spf1 include:missing.example.com -all'});
  assert.ok(has(missing.spf,'No SPF TXT record'));
});
test('SPF static DNS term warnings do not claim a message evaluation result',async()=>{
  const result=await run({}, {'example.com':'v=spf1 '+Array(11).fill('a').join(' ')+' -all'});
  assert.equal(result.spf.lookupTerms,11);assert.equal(result.spf.status,'warning');
  assert.ok(has(result.spf,'evaluated path may exceed'));
});
test('SPF syntax validates addresses, prefixes, modifiers and mechanisms',()=>{
  for(const record of ['v=spf1 +all','v=spf1 ip4:999.1.1.1 -all','v=spf1 ip4:192.0.2.1/33 -all','v=spf1 ip6:2001:db8::/129 -all','v=spf1 wat -all','v=spf1 include -all','v=spf1 redirect=one.example.com redirect=two.example.com','v=spf1 all:example.com','v=spf1 a/33 -all']) assert.ok(parseSpf(record).findings.some(x=>x.level==='error'),record);
  assert.ok(!parseSpf('v=spf1 ip6:2001:db8::/32 a/24//64 -all').findings.some(x=>x.level==='error'));
});
test('SPF unreachable redirect is not queried and macros are not expanded',async()=>{
  const resolver=resolverFor({'example.com':'v=spf1 include:%{d}.provider.com -all redirect=ignored.example.com'});
  const result=await runDnsDiagnostics({fromDomain:'example.com'},{resolver});
  assert.equal(result.spf.incomplete,true);assert.ok(has(result.spf,'macro'));
  assert.ok(!resolver.calls.some(x=>x.includes('%') || x==='ignored.example.com'));
});
test('DNS errors remain unknown instead of being reported as missing SPF or DMARC',async()=>{
  const error=Object.assign(new Error(),{code:'ESERVFAIL'});
  const result=await run({}, {'example.com':error,'_dmarc.example.com':error});
  assert.equal(result.spf.incomplete,true);assert.ok(!has(result.spf,'No SPF TXT record'));
  assert.equal(result.dmarc.policy,null);assert.equal(result.dmarc.incomplete,true);
  assert.ok(has(result.dmarc,'incomplete'));
});
test('DMARC direct policy and strict alignment are independent of successful authentication',async()=>{
  const result=await run({envelopeDomain:'bounce.example.com',dkimDomain:'example.com'}, {'_dmarc.example.com':policy+'; aspf=s; adkim=s'});
  assert.equal(result.dmarc.policyDomain,'example.com');assert.equal(result.dmarc.policy.direct,'reject');
  assert.equal(result.alignment[0].status,'not-aligned');assert.equal(result.alignment[1].status,'aligned');
  assert.match(result.scope,/not evaluated/);
});
test('DMARC inherited sp and np remain conditional on domain existence',async()=>{
  const result=await run({fromDomain:'mail.example.com'}, {'_dmarc.example.com':policy+'; sp=quarantine; np=reject'});
  assert.equal(result.dmarc.policyDomain,'example.com');assert.equal(result.dmarc.organizationalDomain,'example.com');
  assert.equal(result.dmarc.policy.existingSubdomain,'quarantine');assert.equal(result.dmarc.policy.nonexistentSubdomain,'reject');
});
test('DMARC relaxed alignment compares discovered organizational domains, not suffix guesses',async()=>{
  const result=await run({fromDomain:'mail.example.com',envelopeDomain:'bounce.example.com',dkimDomain:'example.net'}, {'_dmarc.example.com':policy,'_dmarc.example.net':policy});
  assert.equal(result.alignment[0].status,'aligned');assert.equal(result.alignment[1].status,'not-aligned');
});
test('DMARC organizational boundaries honor psd=n and public suffix psd=y',async()=>{
  const boundary=await run({fromDomain:'mail.tenant.example.com',envelopeDomain:'bounce.example.com'}, {'_dmarc.tenant.example.com':policy,'_dmarc.example.com':policy});
  assert.equal(boundary.dmarc.organizationalDomain,'tenant.example.com');assert.equal(boundary.alignment[0].status,'not-aligned');
  const psd=await run({fromDomain:'mail.example.co.uk',envelopeDomain:'bounce.example.co.uk'}, {'_dmarc.co.uk':policy.replace('psd=n','psd=y')});
  assert.equal(psd.dmarc.organizationalDomain,'example.co.uk');assert.equal(psd.dmarc.policyDomain,'co.uk');assert.equal(psd.alignment[0].status,'aligned');
});
test('DMARC longest tree walk uses at most eight target names',async()=>{
  const result=await run({fromDomain:'a.b.c.d.e.f.g.h.i.j.mail.example.com'});
  const names=result.queries.filter(q=>q.name.startsWith('_dmarc.')).map(q=>q.name);
  assert.equal(names.length,8);assert.equal(names[1],'_dmarc.g.h.i.j.mail.example.com');assert.equal(names.at(-1),'_dmarc.com');
});
test('DMARC duplicate records are discarded and parent policy may apply',async()=>{
  const result=await run({fromDomain:'mail.example.com'}, {'_dmarc.mail.example.com':[[policy],[policy]],'_dmarc.example.com':policy});
  assert.equal(result.dmarc.policyDomain,'example.com');assert.ok(has(result.dmarc,'Multiple DMARC records'));
});
test('DMARC invalid duplicate tags, version order and case are diagnosed',()=>{
  assert.equal(parseDmarc('v=DMARC1; p=reject; p=none').usable,false);
  assert.equal(parseDmarc('p=reject; v=DMARC1').usable,false);
  assert.equal(parseDmarc('v=dmarc1; p=reject').usable,false);
  assert.equal(parseDmarc('v=DMARC1; p=invalid').usable,false);
  assert.equal(parseDmarc('v=DMARC1; p=invalid; rua=mailto:reports@example.com').policy,'none');
  assert.equal(parseDmarc('v=DMARC1; p=invalid; rua=mailto:reports@example.com').usable,true);
});
test('DMARC current defaults and legacy/test settings are explicit',()=>{
  const result=parseDmarc('v=DMARC1; rua=mailto:reports@example.com; t=y; pct=50; aspf=wrong');
  assert.equal(result.policy,'none');assert.equal(result.aspf,'r');assert.equal(result.testMode,true);
  assert.ok(has(result,'legacy'));assert.ok(has(result,'reduced'));
});
test('DMARC missing policies or DNS failure leave alignment unknown, not passed',async()=>{
  const missing=await run({envelopeDomain:'example.com'});
  assert.equal(missing.alignment[0].status,'unknown');
  const error=Object.assign(new Error(),{code:'ETIMEOUT'});
  const unknown=await run({envelopeDomain:'bounce.example.com'}, {'_dmarc.example.com':policy,'_dmarc.bounce.example.com':error});
  assert.equal(unknown.alignment[0].status,'unknown');
});
test('DKIM selectors are not guessed; omitted selectors are not a missing-key failure',async()=>{
  const result=await run();assert.equal(result.dkim.status,'not-tested');assert.equal(result.dkim.selectors.length,0);
  assert.ok(!result.queries.some(q=>q.name.includes('_domainkey')));
});
test('DKIM validates RSA and Ed25519 public keys and strength',()=>{
  assert.equal(parseDkim(rsa2048).status,'ok');assert.equal(parseDkim(rsa2048).bits,2048);
  assert.equal(parseDkim(rsa1024).status,'warning');
  const ed=generateKeyPairSync('ed25519').publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('base64');
  assert.equal(parseDkim(`v=DKIM1; k=ed25519; p=${ed}`).status,'ok');
});
test('DKIM flags revoked, malformed, unsupported and restricted keys',()=>{
  for(const record of ['v=DKIM1; p=','v=DKIM1; k=rsa','v=DKIM1; p=not-a-key','v=DKIM1; p=AAAA','v=DKIM1; p=AAA=; k=ed25519','v=DKIM1; p=AAA; p=AAA',rsa2048+'; h=sha1',rsa2048+'; s=other',rsa2048.replace('k=rsa','k=other')]) assert.equal(parseDkim(record).status,'error',record.slice(0,60));
  assert.equal(parseDkim(rsa2048+'; t=y').status,'warning');
});
test('DKIM resolves selected names, joins chunks and preserves independent selector results',async()=>{
  const result=await run({selectors:'selector1, selector2'}, {'selector1._domainkey.example.com':[[rsa2048.slice(0,100),rsa2048.slice(100)]]});
  assert.equal(result.dkim.selectors[0].status,'ok');assert.equal(result.dkim.selectors[0].bits,2048);
  assert.equal(result.dkim.selectors[1].status,'error');assert.equal(result.dkim.status,'error');
});
test('DKIM DNS failure is unknown rather than a missing key',async()=>{
  const result=await run({selectors:'s1'}, {'s1._domainkey.example.com':Object.assign(new Error(),{code:'ESERVFAIL'})});
  assert.equal(result.dkim.selectors[0].status,'warning');assert.ok(has(result.dkim,'unknown'));assert.ok(!has(result.dkim,'No DKIM'));
});
test('DNS request budgets, oversized responses and cancellation are bounded',async()=>{
  const capped=await run({}, {}, {limits:{maxQueries:1}});
  assert.ok(capped.queries.length<=1);assert.ok(has(capped,'QUERY_LIMIT'));
  const big=await run({}, {'example.com':rr('v=spf1 '+'a'.repeat(17000))});assert.ok(has(big,'RESPONSE_LIMIT'));
  const controller=new AbortController();controller.abort();
  const cancelled=await run({}, {}, {signal:controller.signal});assert.equal(cancelled.queries.length,0);assert.ok(has(cancelled,'DEADLINE'));
});


test('SPF service-label includes and redirects work with normal provider records',async()=>{
 const result=await run({}, {'example.com':'v=spf1 include:_spf.provider.com -all','_spf.provider.com':'v=spf1 redirect=_spf2.provider.com','_spf2.provider.com':'v=spf1 ip4:192.0.2.1 -all'});
 assert.equal(result.spf.status,'ok');assert.equal(result.spf.nodes.length,3);
});
test('SPF macros with transform delimiters remain incomplete, not a syntax verdict',async()=>{
 const result=await run({}, {'example.com':'v=spf1 exists:%{ir}.%{v}._spf.%{d2} -all'});
 assert.equal(result.spf.incomplete,true);assert.equal(result.spf.status,'warning');
});


test('a stalled DNS resolver is bounded by the overall request deadline',async()=>{
 const result=await run({}, {'example.com':()=>new Promise(()=>{})}, {limits:{timeoutMs:20}});
 assert.equal(result.spf.incomplete,true);assert.ok(has(result,'ECANCELLED') || has(result,'ETIMEOUT'));
 assert.equal(result.dmarc.policy,null);
});
test('large SPF term lists stop inspection with an explicit incomplete warning',async()=>{
 const result=await run({}, {'example.com':'v=spf1 '+Array(201).fill('a').join(' ')+' -all'});
 assert.equal(result.spf.incomplete,true);assert.equal(result.spf.status,'warning');assert.ok(has(result.spf,'200-term'));
});


test('DKIM tag whitespace and colon-separated restrictions are parsed without false failures',()=>{
 const record=rsa2048.replace('v=DKIM1','v = DKIM1')+'; h=sha256 : other; s=other : email';
 assert.equal(parseDkim(record).status,'ok');
});
