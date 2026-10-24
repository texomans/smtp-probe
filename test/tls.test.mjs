import test from 'node:test';
import assert from 'node:assert/strict';
import tls from 'node:tls';
import net from 'node:net';
import {spawn} from 'node:child_process';
import {createHmac} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import path from 'node:path';

const root=path.dirname(fileURLToPath(import.meta.url));
const key=await readFile(path.join(root,'fixtures','smtp-test.key'));
const cert=await readFile(path.join(root,'fixtures','smtp-test.crt'));

function attachSmtpConversation(socket, activeTls, events, messages, options = {}) {
  if (activeTls) socket.write('220 smtp.mock.example ready\r\n');
  let buffer='';
  let inData=false;
  let messageLines=[];
  let loginStep=0;
  let cramPending=false;
  function onData(chunk) {
    buffer+=chunk.toString('utf8');
    let index;
    while((index=buffer.indexOf('\n'))>=0){
      const line=buffer.slice(0,index).replace(/\r$/,'');buffer=buffer.slice(index+1);
      if (inData) {
        if (line === '.') {
          inData=false;
          messages.push(messageLines.join('\r\n'));
          messageLines=[];
          socket.write(options.rejectStage === 'accept' ? '554 5.7.1 policy rejected message\r\n' : '250 2.0.0 message accepted - queued as ABC123\r\n');
          events.push('message received');
        }
        else { messageLines.push(line); events.push('DATA REDACTED'); }
      } else if (line.startsWith('EHLO ')) {
        events.push('EHLO');
        socket.write('250-smtp.mock.example\r\n250-AUTH PLAIN LOGIN CRAM-MD5\r\n250 SIZE 10000\r\n');
      } else if(line.startsWith('AUTH PLAIN ')) {
        const auth = Buffer.from(line.slice('AUTH PLAIN '.length),'base64').toString('utf8');
        events.push('AUTH PLAIN');
        socket.write(!options.rejectAuth && auth === '\0smtp-tester\0a-unique-secret-password' ? '235 2.7.0 Authenticated\r\n' : '535 5.7.8 Bad credentials\r\n');
      } else if(line === 'AUTH LOGIN') {
        loginStep=1; events.push('AUTH LOGIN'); socket.write('334 VXNlcm5hbWU6\r\n');
      } else if(loginStep===1) {
        loginStep=2; events.push('LOGIN USER');
        socket.write(Buffer.from(line,'base64').toString('utf8')==='smtp-tester' ? '334 UGFzc3dvcmQ6\r\n' : '535 5.7.8 Unknown user\r\n');
      } else if(loginStep===2) {
        loginStep=0; events.push('LOGIN PASS');
        socket.write(Buffer.from(line,'base64').toString('utf8')==='a-unique-secret-password' ? '235 2.7.0 Authenticated\r\n' : '535 5.7.8 Incorrect password\r\n');
      } else if(line==='AUTH CRAM-MD5') {
        cramPending=true; events.push('AUTH CRAM-MD5');
        socket.write(`334 ${Buffer.from('smtp-probe-test-challenge').toString('base64')}\r\n`);
      } else if(cramPending) {
        cramPending=false; events.push('CRAM RESPONSE');
        const mac=createHmac('md5','a-unique-secret-password').update('smtp-probe-test-challenge').digest('hex');
        socket.write(Buffer.from(line,'base64').toString('utf8')===`smtp-tester ${mac}` ? '235 2.7.0 Authenticated\r\n' : '535 5.7.8 Incorrect response\r\n');
      } else if(line === 'MAIL FROM:<sender@example.net>') {events.push('MAIL FROM');socket.write(options.rejectStage === 'mail' ? '550 5.7.1 sender rejected\r\n' : '250 sender ok\r\n');}
      else if(line === 'RCPT TO:<recipient@example.net>') {events.push('RCPT TO');socket.write(options.rejectStage === 'rcpt' ? '550 5.1.1 unknown recipient\r\n' : '250 recipient ok\r\n');}
      else if(line === 'DATA') {if(options.rejectStage !== 'data') inData=true;socket.write(options.rejectStage === 'data' ? '554 5.7.1 DATA rejected\r\n' : '354 Send message\r\n');}
      else if(line === 'QUIT') {socket.write('221 bye\r\n');socket.end();}
      else {events.push(`unexpected command: ${line}`);socket.write('500 Unexpected command\r\n');}
    }
  }
  socket.on('data',onData);
  socket.on('error',()=>{});
}

async function startServer(options={}) {
  const events=[];
  const messages=[];
  const server=tls.createServer({key,cert},socket=>attachSmtpConversation(socket,true,events,messages,options));
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  return {server,events,messages,port:server.address().port};
}
function runClient(port, mode, options={}) {
  return new Promise((resolve,reject)=>{
    const cmd=path.join(root,'fixtures','client.mjs');
    const args=[cmd];
    const env={...process.env,NODE_EXTRA_CA_CERTS:path.join(root,'fixtures','smtp-test.crt'),MOCK_PORT:String(port),MOCK_TLS:options.tlsMode || 'implicit',MOCK_MODE:mode,MOCK_AUTH: options.auth || 'auto', MOCK_HOST:options.host || 'smtp.mock.example'};
    const child=spawn(process.execPath,args,{env});
    let stdout='',stderr='';
    child.stdout.on('data',c=>stdout+=c);
    child.stderr.on('data',c=>stderr+=c);
    child.on('error',reject);
    child.on('exit',code=>{
      if(code!==0) reject(new Error(`client exit ${code}: ${stderr}`));
      else {try{resolve(JSON.parse(stdout.trim()));}catch(e){reject(new Error(`Bad output: ${stdout} ; ${stderr}`));}}
    });
  });
}

test('Implicit TLS: TLS certificate valid, AUTH PLAIN transcript redacted',async()=>{
 const mock=await startServer();
 try {
  const {result,events}=await runClient(mock.port,'verify');
  assert.equal(result.ok,true,result.message);
  assert.equal(result.tls.authorized,true);
  assert.ok(['A','B'].includes(result.grading.grade));
  assert.ok(!JSON.stringify(result.grading).includes('a-unique-secret-password'));
  assert.ok(!JSON.stringify(result.grading).includes('smtp-tester'));
  assert.match(result.tls.protocol,/TLSv1\.[23]/);
  assert.equal(result.tls.certificateChain[0].subject,'smtp.mock.example');
  const transcript=events.filter(e=>e.text).map(e=>e.text).join('\n');
  assert.ok(transcript.includes('AUTH PLAIN [REDACTED]'));
  assert.ok(!transcript.includes('a-unique-secret-password'));
  assert.ok(!transcript.includes('smtp-tester'));
  assert.ok(mock.events.includes('AUTH PLAIN'));
 }finally{await new Promise(resolve=>mock.server.close(resolve));}
});

test('Implicit TLS: single-recipient send completes after authentication',async()=>{
 const mock=await startServer();
 try {
  const {result,events}=await runClient(mock.port,'send');
  assert.equal(result.ok,true,result.message);
  assert.ok(mock.events.includes('message received'));
  assert.equal(result.delivery.recipient,'recipient@example.net');
  assert.equal(result.delivery.smtpCode,250);
  assert.equal(result.grading.connectivity.checks.find(x=>x.id==='submission').status,'pass');
  assert.match(result.delivery.smtpResponse,/queued as ABC123/);
  assert.match(result.messageId,/smtp-probe\.local/);
  assert.equal(mock.messages.length,1);
  assert.match(mock.messages[0],/Content-Transfer-Encoding: base64/);
  const body=mock.messages[0].split('\r\n\r\n')[1];
  assert.equal(Buffer.from(body.replaceAll('\r\n',''),'base64').toString('utf8'),'Hello from test.\n.Line beginning with dot.');
  const transcript=events.filter(e=>e.text).map(e=>e.text).join('\n');
  assert.ok(transcript.includes('[message data redacted'));
  assert.ok(!transcript.includes('Line beginning with dot'));
  assert.ok(!transcript.includes('a-unique-secret-password'));
 }finally{await new Promise(resolve=>mock.server.close(resolve));}
});


test('AUTH LOGIN: two-stage credential exchange succeeds without leaking base64 secrets',async()=>{
 const mock=await startServer();
 try {
  const {result,events}=await runClient(mock.port,'verify',{auth:'login'});
  assert.equal(result.ok,true,result.message);
  assert.ok(mock.events.includes('AUTH LOGIN'));
  const transcript=events.filter(e=>e.text).map(e=>e.text).join('\n');
  assert.ok(transcript.includes('[REDACTED USERNAME]'));
  assert.ok(transcript.includes('[REDACTED PASSWORD]'));
  assert.ok(!transcript.includes('a-unique-secret-password'));
 } finally {await new Promise(resolve=>mock.server.close(resolve));}
});

test('CRAM-MD5: authentication mechanism succeeds with redacted response',async()=>{
 const mock=await startServer();
 try {
  const {result,events}=await runClient(mock.port,'verify',{auth:'cram-md5'});
  assert.equal(result.ok,true,result.message);
  assert.ok(mock.events.includes('AUTH CRAM-MD5'));
  const transcript=events.filter(e=>e.text).map(e=>e.text).join('\n');
  assert.ok(transcript.includes('[REDACTED AUTH RESPONSE]'));
 } finally {await new Promise(resolve=>mock.server.close(resolve));}
});

test('TLS refuses a certificate valid for a different hostname',async()=>{
 const mock=await startServer();
 try {
  const {result}=await runClient(mock.port,'verify',{host:'wrong.mock.example'});
  assert.equal(result.ok,false);
  assert.match(result.message,/TLS negotiation failed/i);
  assert.equal(result.grading.grade,'F');
  assert.equal(result.grading.connectivity.checks.find(x=>x.id==='tls').status,'fail');
  assert.ok(!mock.events.includes('AUTH PLAIN'));
 } finally {await new Promise(resolve=>mock.server.close(resolve));}
});

for (const rejectStage of ['mail','rcpt','data','accept']) {
  test(`SMTP server rejecting the ${rejectStage} step fails with code and does not falsely report delivery`, async()=>{
    const mock=await startServer({rejectStage});
    try {
      const {result,events}=await runClient(mock.port,'send');
      assert.equal(result.ok,false);
      assert.equal(result.smtpCode, rejectStage==='data'||rejectStage==='accept' ? 554 : 550);
      assert.equal(result.stage,'send');
      assert.equal(result.delivery,undefined);
      assert.ok(['A','B'].includes(result.grading.grade));
      assert.equal(result.grading.connectivity.status,'fail');
      assert.equal(result.grading.connectivity.checks.find(x=>x.id==='submission').status,'fail');
      assert.ok(events.some(e=>e.type==='transcript'&&e.kind==='error'));
      const transcript=events.filter(e=>e.text).map(e=>e.text).join('\n');
      assert.ok(!transcript.includes('a-unique-secret-password'));
      if (rejectStage==='mail') assert.equal(mock.events.includes('RCPT TO'),false);
      if (rejectStage==='rcpt') assert.equal(mock.events.includes('DATA'),false);
      if (rejectStage==='data') assert.equal(mock.events.includes('message received'),false);
    } finally {await new Promise(resolve=>mock.server.close(resolve));}
  });
}


test('authentication rejection keeps transport grade and fails authentication connectivity',async()=>{
 const mock=await startServer({rejectAuth:true});
 try {
  const {result}=await runClient(mock.port,'verify');
  assert.equal(result.ok,false);
  assert.equal(result.smtpCode,535);
  assert.ok(['A','B'].includes(result.grading.grade));
  assert.equal(result.grading.connectivity.status,'fail');
  assert.equal(result.grading.connectivity.checks.find(x=>x.id==='auth').status,'fail');
 } finally {await new Promise(resolve=>mock.server.close(resolve));}
});
