import test from 'node:test';
import assert from 'node:assert/strict';
import { gradeConnection } from '../src/grading.mjs';
const now = Date.parse('2026-10-24T12:00:00Z');
const config = {tlsMode:'implicit'};
const evidence = {tcp:'pass', greeting:'pass', ehlo:'pass', tls:'pass'};
const result = {ok:true, tls:{authorized:true, protocol:'TLSv1.3', cipher:'TLS_AES_256_GCM_SHA384', certificateChain:[{expires:'2027-10-24T12:00:00Z'}]}, capabilities:['smtp.example','AUTH PLAIN LOGIN','SIZE 10000']};
const grade = (r=result, e=evidence, c=config) => gradeConnection(c, r, e, now);
test('validated modern TLS earns A; untested authentication is explicit', () => {
  const g=grade(); assert.equal(g.grade,'A'); assert.equal(g.connectivity.status,'pass');
  assert.equal(g.connectivity.checks.find(x=>x.id==='auth').status,'not-tested');
  assert.match(g.checks.find(x=>x.id==='auth-methods').detail,/PLAIN, LOGIN/);
  assert.match(g.scope,/Other TLS versions/);
});
test('TLS 1.2 with ECDHE and AEAD earns B', () => {
  assert.equal(grade({...result,tls:{...result.tls,protocol:'TLSv1.2',cipher:'ECDHE-RSA-AES256-GCM-SHA384'}}).grade,'B');
});
test('unrecognized or non-forward-secret cipher needs review', () => {
  for(const cipher of ['AES256-GCM-SHA384', 'ECDHE-RSA-AES256-SHA', null]) assert.equal(grade({...result,tls:{...result.tls,cipher}}).grade,'C');
});
test('certificate near expiry caps A at B; expired certificate fails', () => {
  for(const [expires,expected] of [['2026-11-23T12:00:00Z','B'],['2026-10-23T12:00:00Z','F']]) {
    assert.equal(grade({...result,tls:{...result.tls,certificateChain:[{expires}]}}).grade,expected);
  }
});
test('missing expiry is unknown rather than a fabricated date', () => {
  assert.equal(grade({...result,tls:{...result.tls,certificateChain:[]}}).checks.find(x=>x.id==='expiry').status,'unknown');
});
test('obsolete or unknown TLS version fails', () => {
  for(const protocol of ['TLSv1.1','unknown']) assert.equal(grade({...result,tls:{...result.tls,protocol}}).grade,'F');
});
test('plaintext connection fails security even when connectivity passes', () => {
  const g=grade({ok:true,tls:null,capabilities:[]},{tcp:'pass',greeting:'pass',ehlo:'pass'},{tlsMode:'none'});
  assert.equal(g.grade,'F'); assert.equal(g.connectivity.status,'pass'); assert.match(g.summary,/unencrypted/);
});
test('TLS failure and missing required STARTTLS fail without inferring certificate cause', () => {
  for(const e of [{tcp:'pass',tls:'fail'},{tcp:'pass',ehlo:'pass',starttls:false}]) {
    const g=grade({ok:false,tls:null},e,{tlsMode:'starttls'}); assert.equal(g.grade,'F');
    assert.equal(g.checks.find(x=>x.id==='certificate').status,'unknown');
  }
});
test('TCP failure leaves security ungraded', () => {
  const g=grade({ok:false,tls:null},{tcp:'fail'}); assert.equal(g.grade,'N/A'); assert.equal(g.connectivity.status,'fail');
});
test('auth rejection and submission rejection do not erase validated transport', () => {
  for(const id of ['auth','submission']) {
    const g=grade({...result,ok:false},{...evidence,[id]:'fail'});
    assert.equal(g.grade,'A'); assert.equal(g.connectivity.status,'fail');
    assert.equal(g.connectivity.checks.find(x=>x.id===id).status,'fail');
  }
});
test('AUTH absence is informational; plaintext advertisement is a warning, not acceptance', () => {
  const g=grade({...result,capabilities:['smtp.example','SIZE 1000']},{...evidence,plaintextAuth:true});
  assert.equal(g.grade,'A'); assert.match(g.checks.find(x=>x.id==='auth-methods').detail,/normal/);
  assert.match(g.checks.find(x=>x.id==='plaintext-auth').detail,/not tested/);
});
test('AUTH= and multiple AUTH lines are combined and deduplicated', () => {
  const g=grade({...result,capabilities:['AUTH=PLAIN LOGIN','AUTH LOGIN XOAUTH2']});
  assert.equal(g.checks.find(x=>x.id==='auth-methods').detail,'PLAIN, LOGIN, XOAUTH2');
});
