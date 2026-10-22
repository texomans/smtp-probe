import test from 'node:test';
import assert from 'node:assert/strict';
import { createTestLimiter } from '../src/rate-limit.mjs';

const policy = {
  verify: {perIp:3,perIpMs:1000,perHost:4,perHostMs:2000,perIdentity:2,perIdentityMs:5000,global:20,globalMs:6000},
  send: {perIp:1,perIpMs:1000,perHost:1,perHostMs:2000,perIdentity:1,perIdentityMs:5000,global:2,globalMs:6000},
};
function checker() { let ms=100;return { limiter:createTestLimiter({now:()=>ms,policy}), advance:n=>{ms+=n;} }; }
const req=(ip,host,username,mode='verify')=>({ip,host,username,mode});

test('A single SMTP identity cannot attempt unlimited logins across different IPs',()=>{
  const {limiter}=checker();
  assert.equal(limiter.allow(req('1.1.1.1','smtp.example.com','alice')),true);
  assert.equal(limiter.allow(req('2.2.2.2','smtp.example.com','alice')),true);
  assert.equal(limiter.allow(req('3.3.3.3','smtp.example.com','alice')),false);
  assert.equal(limiter.allow(req('3.3.3.3','smtp.example.com','bob')),true);
});
test('SMTP host is capped even when sender usernames and source IPs change',()=>{
  const {limiter}=checker();
  for(let n=0;n<4;n++) assert.equal(limiter.allow(req(`1.1.1.${n}`,'smtp.example.com',`user${n}`)),true);
  assert.equal(limiter.allow(req('9.9.9.9','smtp.example.com','fresh')),false);
  assert.equal(limiter.allow(req('9.9.9.9','another.example.com','fresh')),true);
});
test('Individual IP quota is checked before attempts are consumed',()=>{
  const {limiter}=checker();
  for(let n=0;n<3;n++) assert.equal(limiter.allow(req('1.1.1.1',`mail${n}.example.com`,'test')),true);
  assert.equal(limiter.allow(req('1.1.1.1','fourth.example.com','test')),false);
  assert.equal(limiter.allow(req('2.2.2.2','fourth.example.com','test')),true);
});
test('Send quota is independent from verify, and denied requests do not burn another quota',()=>{
  const {limiter}=checker();
  assert.equal(limiter.allow(req('1.1.1.1','smtp.example.com','alice','send')),true);
  assert.equal(limiter.allow(req('2.2.2.2','smtp.example.com','bob','send')),false);
  assert.equal(limiter.allow(req('2.2.2.2','smtp.example.com','bob','verify')),true);
  assert.equal(limiter.allow(req('2.2.2.2','second.example.com','bob','send')),true);
});
test('Windows expire and rates recover without application restart',()=>{
  const {limiter,advance}=checker();
  assert.equal(limiter.allow(req('1.1.1.1','smtp.example.com','alice')),true);
  assert.equal(limiter.allow(req('1.1.1.1','smtp.example.com','alice')),true);
  assert.equal(limiter.allow(req('1.1.1.1','smtp.example.com','alice')),false);
  advance(5001);
  assert.equal(limiter.allow(req('1.1.1.1','smtp.example.com','alice')),true);
});
