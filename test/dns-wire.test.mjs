import test from 'node:test';
import assert from 'node:assert/strict';
import dgram from 'node:dgram';
import { Resolver } from 'node:dns/promises';
import { generateKeyPairSync } from 'node:crypto';
import { runDnsDiagnostics } from '../src/email-auth.mjs';
function nameBytes(name) {return Buffer.concat([...name.split('.').map(label=>Buffer.concat([Buffer.from([label.length]),Buffer.from(label)])),Buffer.from([0])]);}
function record(name,type,data) {
 const header=Buffer.alloc(10);header.writeUInt16BE(type,0);header.writeUInt16BE(1,2);header.writeUInt32BE(60,4);header.writeUInt16BE(data.length,8);
 return Buffer.concat([nameBytes(name),header,data]);
}
function txt(name,value) {
 const chunks=[];
 for(let i=0;i<value.length;i+=200){const chunk=Buffer.from(value.slice(i,i+200));chunks.push(Buffer.from([chunk.length]),chunk);}
 return record(name,16,Buffer.concat(chunks));
}
test('real DNS resolver follows CNAME DKIM delegation and joins wire TXT chunks',async t=>{
 const key=generateKeyPairSync('rsa',{modulusLength:2048}).publicKey.export({format:'der',type:'spki'}).toString('base64');
 const records={
  'example.com':[txt('example.com','v=spf1 include:_spf.provider.com -all')],
  '_spf.provider.com':[txt('_spf.provider.com','v=spf1 ip4:192.0.2.0/24 -all')],
  '_dmarc.example.com':[txt('_dmarc.example.com','v=DMARC1; p=reject; psd=n; rua=mailto:reports@example.com')],
  'selector1._domainkey.example.com':[
    record('selector1._domainkey.example.com',5,nameBytes('key.provider.com')),
    txt('key.provider.com',`v=DKIM1; k=rsa; p=${key}`),
  ],
 };
 const server=dgram.createSocket('udp4');t.after(()=>server.close());
 server.on('message',(query,remote)=>{
  let at=12;const labels=[];
  while(query[at]){const length=query[at++];labels.push(query.subarray(at,at+length).toString());at+=length;}
  at+=5;
  const name=labels.join('.'),answers=records[name] || [];
  const header=Buffer.alloc(12);header.writeUInt16BE(query.readUInt16BE(0),0);header.writeUInt16BE(0x8180,2);header.writeUInt16BE(1,4);header.writeUInt16BE(answers.length,6);
  server.send(Buffer.concat([header,query.subarray(12,at),...answers]),remote.port,remote.address);
 });
 await new Promise(resolve=>server.bind(0,'127.0.0.1',resolve));
 const resolver=new Resolver({timeout:1000,tries:1});resolver.setServers([`127.0.0.1:${server.address().port}`]);t.after(()=>resolver.cancel());
 const result=await runDnsDiagnostics({fromDomain:'example.com',envelopeDomain:'example.com',selectors:'selector1'},{resolver});
 assert.equal(result.spf.status,'ok');assert.equal(result.spf.nodes.length,2);
 assert.equal(result.dmarc.policy.direct,'reject');
 assert.equal(result.dkim.selectors[0].status,'ok');assert.equal(result.dkim.selectors[0].bits,2048);
 assert.equal(result.alignment[0].status,'aligned');
 assert.ok(result.queries.every(query=>query.status==='ok'));
});
