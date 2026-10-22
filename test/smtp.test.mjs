import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import {runSmtpTest} from '../src/smtp.mjs';

function createMockSmtp(options={}) {
 return new Promise((resolve,reject)=>{
  const actions=[];
  const server=net.createServer(socket=>{
    socket.write('220 smtp.mock.example ESMTP ready\r\n');
    let buffer='';
    socket.on('error',()=>{});
    socket.on('data',data=>{
      buffer+=data.toString('utf8');
      let at;
      while ((at=buffer.indexOf('\n'))>=0) {
        const line=buffer.slice(0,at).replace(/\r$/,''); buffer=buffer.slice(at+1);
        actions.push(line);
        if(line.startsWith('EHLO')){
          socket.write(options.noStarttls ? '250-smtp.mock.example\r\n250 SIZE 10000\r\n' : '250-smtp.mock.example\r\n250-STARTTLS\r\n250 SIZE 10000\r\n');
        } else if(line==='QUIT'){socket.write('221 2.0.0 bye\r\n'); socket.end();}
        else if(line==='NOOP'){socket.write('250 OK\r\n');}
        else {socket.write('500 unsupported\r\n');}
      }
    });
  });
  server.listen(0,'127.0.0.1',()=>resolve({server,port:server.address().port,actions}));
  server.on('error',reject);
 });
}
const cfg={host:'smtp.mock.example', tlsMode:'none',mode:'verify',username:'',password:'',authMethod:'auto'};
const target={address:'127.0.0.1',family:4,host:'smtp.mock.example'};

test('Reports the real banner and a multiline EHLO conversation',async()=>{
 const mock=await createMockSmtp();
 try {
  const events=[];
  const result=await runSmtpTest({...cfg,port:mock.port},target,event=>events.push(event));
  assert.equal(result.ok,true, result.message);
  assert.ok(events.some(e=>e.type==='transcript' && e.text?.includes('220 smtp.mock.example')));
  assert.ok(events.some(e=>e.type==='transcript' && e.text?.includes('250-STARTTLS')));
  assert.ok(events.some(e=>e.type==='transcript' && e.text?.includes('EHLO smtp-probe.local')));
  assert.ok(result.capabilities.includes('STARTTLS'));
  assert.ok(mock.actions.some(x=>x.startsWith('EHLO')));
 } finally {await new Promise(resolve=>mock.server.close(resolve));}
});

test('Fails closed when STARTTLS is not advertised',async()=>{
 const mock=await createMockSmtp({noStarttls:true});
 try {
  const events=[];
  const result=await runSmtpTest({...cfg,tlsMode:'starttls',port:mock.port},target,event=>events.push(event));
  assert.equal(result.ok,false);
  assert.match(result.message,/STARTTLS is not advertised/);
 } finally {await new Promise(resolve=>mock.server.close(resolve));}
});
