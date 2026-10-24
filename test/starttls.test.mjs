import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import tls from 'node:tls';
import {spawn} from 'node:child_process';
import {readFile} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const base=path.dirname(fileURLToPath(import.meta.url));
const key=await readFile(path.join(base,'fixtures','smtp-test.key'));
const cert=await readFile(path.join(base,'fixtures','smtp-test.crt'));

function startServer(options = {}) {
 return new Promise((resolve,reject)=>{
  const context=tls.createSecureContext({key,cert});
  const seen=[];
  const server=net.createServer(socket=>{
    let buffer='';
    let secured=false;
    socket.on('error',()=>{});
    function dataHandler(chunk){
      buffer+=chunk.toString('utf8');
      let index;
      while((index=buffer.indexOf('\n'))>=0){
        const line=buffer.slice(0,index).replace(/\r$/,'');
        buffer=buffer.slice(index+1);
        if(line.startsWith('EHLO ')){
          seen.push(secured?'TLS EHLO':'PLAIN EHLO');
          if (secured && options.rejectEhlo) {socket.write('500 EHLO rejected after TLS\r\n'); continue;}
          socket.write(secured ? '250-smtp.mock.example\r\n250 AUTH PLAIN LOGIN\r\n' : '250-smtp.mock.example\r\n250 STARTTLS\r\n');
        } else if(line === 'STARTTLS' && !secured) {
          seen.push('STARTTLS');
          socket.removeListener('data',dataHandler);
          socket.write('220 Ready for TLS\r\n');
          const secure = new tls.TLSSocket(socket,{isServer:true,secureContext:context});
          secure.on('error',()=>{});
          secure.once('secure',()=>{
            secured=true;
            socket=secure;
            buffer='';
            socket.on('data',dataHandler);
          });
        } else if (line.startsWith('AUTH PLAIN ')) {
          seen.push('AUTH');
          const value=Buffer.from(line.slice(11),'base64').toString('utf8');
          socket.write(value==='\0smtp-tester\0a-unique-secret-password' ? '235 2.7.0 OK\r\n' : '535 5.7.8 Bad password\r\n');
        } else if(line==='QUIT') {socket.write('221 bye\r\n');socket.end();}
        else {seen.push(`unexpected ${line}`);socket.write('500 unsupported\r\n');}
      }
    }
    socket.on('data',dataHandler);
    socket.write('220 smtp.mock.example ready\r\n');
  });
  server.listen(0,'127.0.0.1',()=>resolve({server,port:server.address().port,seen}));
  server.on('error',reject);
 });
}
function client(port) {
 return new Promise((resolve,reject)=>{
  const proc=spawn(process.execPath,[path.join(base,'fixtures','client.mjs')],{
   env:{...process.env,NODE_EXTRA_CA_CERTS:path.join(base,'fixtures','smtp-test.crt'),MOCK_PORT:String(port),MOCK_TLS:'starttls',MOCK_MODE:'verify'}
  });
  let stdout='',stderr='';
  proc.stdout.on('data',chunk=>stdout+=chunk);
  proc.stderr.on('data',chunk=>stderr+=chunk);
  proc.on('error',reject);
  proc.on('close',code=>{
    if(code!==0) reject(new Error(stderr));
    else try{resolve(JSON.parse(stdout));}catch(e){reject(e);}
  });
 });
}
test('STARTTLS clears and re-queries capabilities; auth occurs only after TLS',async()=>{
 const mock=await startServer();
 try {
  const {result,events}=await client(mock.port);
  assert.equal(result.ok,true,`${result.message} (${result.stage})`);
  assert.ok(mock.seen.includes('PLAIN EHLO'));
  assert.ok(mock.seen.includes('STARTTLS'));
  assert.ok(mock.seen.includes('TLS EHLO'));
  assert.ok(mock.seen.includes('AUTH'));
  assert.deepEqual(mock.seen.slice(0,4),['PLAIN EHLO','STARTTLS','TLS EHLO','AUTH']);
  assert.equal(result.tls.authorized,true);
  assert.ok(['A','B'].includes(result.grading.grade));
  assert.equal(result.grading.connectivity.checks.find(x=>x.id==='tls').status,'pass');
  assert.equal(result.grading.connectivity.checks.find(x=>x.id==='auth').status,'pass');
  assert.match(result.grading.checks.find(x=>x.id==='auth-methods').detail,/PLAIN/);
  const text=events.filter(x=>x.text).map(x=>x.text).join('\n');
  assert.ok(!text.includes('a-unique-secret-password'));
 } finally {await new Promise(resolve=>mock.server.close(resolve));}
});


test('failed post-STARTTLS EHLO does not reuse pre-TLS capabilities',async()=>{
 const mock=await startServer({rejectEhlo:true});
 try {
  const {result}=await client(mock.port);
  assert.equal(result.ok,false);
  assert.deepEqual(result.capabilities,[]);
  assert.ok(['A','B'].includes(result.grading.grade));
  assert.equal(result.grading.connectivity.checks.find(x=>x.id==='ehlo').status,'fail');
  assert.equal(result.grading.checks.find(x=>x.id==='auth-methods').status,'unknown');
  assert.ok(!mock.seen.includes('AUTH'));
 } finally {await new Promise(resolve=>mock.server.close(resolve));}
});
