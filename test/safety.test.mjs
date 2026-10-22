import test from 'node:test';
import assert from 'node:assert/strict';
import {isPublicIp,validateRequest,resolvePublicTarget,redact,validateSendDeployment,recipientAllowed} from '../src/safety.mjs';

const base={host:'mail.smtp2go.com',port:587,tlsMode:'starttls',mode:'verify',authMethod:'auto',username:'',password:''};

test('Accepts a well-formed, public SMTP connection',()=>{
 const result=validateRequest(base);
 assert.equal(result.host,'mail.smtp2go.com');
});
test('Requires encryption before transmitting SMTP credentials',()=>{
 assert.throws(()=>validateRequest({...base,tlsMode:'none',username:'test',password:'secret'}),/blocked/);
});
test('Requires matching username and password presence',()=>{
 assert.throws(()=>validateRequest({...base,username:'user'}),/both username and password/);
});
test('Denies sending until an administrator explicitly opts in',()=>{
 assert.throws(()=>validateRequest({...base,mode:'send'}),/disabled/);
});
test('Rejects hostname/IP tricks and arbitrary ports',()=>{
 for(const host of ['localhost','127.0.0.1','127.0.0.1.evil.invalid/path','foo..example.com','169.254.169.254','smtp.local']){
   assert.throws(()=>validateRequest({...base,host}),/public SMTP hostname/);
 }
 assert.throws(()=>validateRequest({...base,port:22}),/Port not allowed/);
});
test('Rejects mail header injection',()=>{
 assert.throws(()=>validateRequest({...base,mode:'send',username:'u',password:'p',from:'me@example.com',to:'you@example.com',subject:'Hello\r\nBcc:bad@example.com',message:'Hello'}, {ALLOW_SEND:'1', SMTP_SEND_ALLOWED_HOSTS:'mail.smtp2go.com', SMTP_SEND_ALLOWED_RECIPIENTS:'you@example.com'}),/Invalid subject|Subject must/);
});
test('Explicit IPv4 private/reserved and IPv6 local targets are blocked',()=>{
 for(const ip of ['127.0.0.1','10.4.0.1','172.16.0.7','192.168.1.1','169.254.169.254','100.64.0.1','198.18.1.1','0.0.0.0','224.0.0.1','::1','fd00::1','fe80::1','::ffff:127.0.0.1','2001:db8::1','2002:c0a8:1::1']){
  assert.equal(isPublicIp(ip),false,`Expected blocked: ${ip}`);
 }
 for(const ip of ['1.1.1.1','8.8.8.8','2606:4700:4700::1111']) assert.equal(isPublicIp(ip),true,`Expected public: ${ip}`);
});
test('Refuses DNS results mixing private and public addresses (rebinding defense)',async()=>{
 const fake=async()=>[{address:'1.1.1.1',family:4},{address:'10.0.0.1',family:4}];
 await assert.rejects(()=>resolvePublicTarget('mail.example.com',fake),/private, reserved, or mixed/);
});
test('Resolves a validated IP without connecting via a second hostname lookup',async()=>{
 const fake=async()=>[{address:'8.8.8.8',family:4}];
 assert.deepEqual(await resolvePublicTarget('mail.example.com',fake),{address:'8.8.8.8',family:4,host:'mail.example.com'});
});
test('Redacts cleartext and base64-encoded secrets',()=>{
 const pass='IWillNotPublishThis';
 const user='admin@client.example';
 const message=`Authentication ${pass}, ${user}, ${Buffer.from(pass).toString('base64')}`;
 const result=redact(message,[user,pass]);
 assert.ok(!result.includes(pass));
 assert.ok(!result.includes(user));
 assert.ok(!result.includes(Buffer.from(pass).toString('base64')));
});

test('Allows only an explicit single-recipient send through encrypted, authenticated SMTP',()=>{
  const env={ALLOW_SEND:'1', SMTP_SEND_ALLOWED_HOSTS:'mail.smtp2go.com', SMTP_SEND_ALLOWED_RECIPIENTS:'recipient@example.net'};
  const request={...base, mode:'send',username:'smtp-test-user',password:'some-secret',from:'sender@example.net',to:'recipient@example.net',subject:'Test message',message:'Hello'};
  const config=validateRequest(request,env);
  assert.equal(config.mode,'send');
  assert.equal(config.tlsMode,'starttls');
  assert.equal(config.to,'recipient@example.net');
  assert.throws(()=>validateRequest({...request,to:'a@example.net,b@example.net'},env),/valid recipient/);
});

test('Send mode rejects missing credentials and plaintext authentication even if sending is enabled',()=>{
  const env={ALLOW_SEND:'1', SMTP_SEND_ALLOWED_HOSTS:'mail.smtp2go.com', SMTP_SEND_ALLOWED_RECIPIENTS:'recipient@example.net'};
  const req={...base, mode:'send',from:'sender@example.net',to:'recipient@example.net',subject:'Test message',message:'Hello'};
  assert.throws(()=>validateRequest(req,env),/requires encrypted, authenticated/);
  assert.throws(()=>validateRequest({...req,username:'tester',password:'secret',tlsMode:'none'},env),/blocked/);
});

test('Send mode rejects invalid addresses, header injection, and empty message body',()=>{
  const env={ALLOW_SEND:'1', SMTP_SEND_ALLOWED_HOSTS:'mail.smtp2go.com', SMTP_SEND_ALLOWED_RECIPIENTS:'recipient@example.net'};
  const req={...base, mode:'send',username:'tester',password:'secret',from:'sender@example.net',to:'recipient@example.net',subject:'Test message',message:'Hello'};
  assert.throws(()=>validateRequest({...req,from:'sender@example.net\nCc:evil@example.net'},env),/valid sender/);
  assert.throws(()=>validateRequest({...req,to:'recipient@example.net\r\nBcc:evil@example.net'},env),/valid recipient/);
  assert.throws(()=>validateRequest({...req,message:'   '},env),/body is required/);
});

test('Optional SMTP destination allowlist is exact-match and opt-in',()=>{
  assert.equal(validateRequest(base).host,'mail.smtp2go.com');
  const env={SMTP_ALLOWED_HOSTS:'mail.smtp2go.com,smtp.example.com'};
  assert.equal(validateRequest(base,env).host,'mail.smtp2go.com');
  assert.throws(()=>validateRequest({...base,host:'mail.smtp2go.com.evil.com'},env),/not allowed/);
  assert.throws(()=>validateRequest({...base,host:'other.smtp2go.com'},env),/not allowed/);
});


test('Sending requires a nonempty, syntactically valid recipient allowlist at startup (fail closed)', () => {
  assert.throws(() => validateSendDeployment({ALLOW_SEND:'1'}), /requires a nonempty SMTP_SEND_ALLOWED_RECIPIENTS/);
  assert.throws(() => validateSendDeployment({ALLOW_SEND:'1', SMTP_SEND_ALLOWED_HOSTS:'mail.smtp2go.com'}), /requires a nonempty SMTP_SEND_ALLOWED_RECIPIENTS/);
  assert.throws(() => validateSendDeployment({ALLOW_SEND:'1', SMTP_SEND_ALLOWED_HOSTS:'127.0.0.1', SMTP_SEND_ALLOWED_RECIPIENTS:'you@example.com'}), /invalid host or recipient/);
  assert.throws(() => validateSendDeployment({ALLOW_SEND:'1', SMTP_SEND_ALLOWED_HOSTS:'mail.smtp2go.com', SMTP_SEND_ALLOWED_RECIPIENTS:'everyone'}), /invalid host or recipient/);
  for (const pattern of ['*', '*@*', '*@*.example.com', 'alice@*.example.com', '**@example.com', 'a*b*@example.com', '*@com', 'name@bad..example.com']) {
    assert.throws(() => validateSendDeployment({ALLOW_SEND:'1', SMTP_SEND_ALLOWED_RECIPIENTS:pattern}), /invalid host or recipient/, `Must refuse unsafe recipient policy: ${pattern}`);
  }
  assert.doesNotThrow(() => validateSendDeployment({ALLOW_SEND:'1', SMTP_SEND_ALLOWED_RECIPIENTS:'*@example.org, ops@example.net'}));
  assert.doesNotThrow(() => validateSendDeployment({ALLOW_SEND:'1', SMTP_SEND_ALLOWED_HOSTS:'*', SMTP_SEND_ALLOWED_RECIPIENTS:'person@example.com'}));
  assert.doesNotThrow(() => validateSendDeployment({ALLOW_SEND:'0'}));
});

test('An authorized sender cannot send to a recipient or host outside the exact approved list', () => {
  const env = {
    ALLOW_SEND:'1',
    SMTP_SEND_ALLOWED_HOSTS:'mail.smtp2go.com',
    SMTP_SEND_ALLOWED_RECIPIENTS:'alice@example.org',
  };
  const msg = {...base, mode:'send', username:'tester',password:'secret',from:'sender@example.net',to:'alice@example.org',subject:'Test',message:'Hello'};
  assert.equal(validateRequest(msg,env).to,msg.to);
  assert.throws(() => validateRequest({...msg,to:'other@example.org'},env), /recipient is not permitted/);
  assert.throws(() => validateRequest({...msg,host:'smtp.evil.com'},env), /SMTP host is not permitted/);
  assert.throws(() => validateRequest({...msg,to:'alice@example.org.evil.com'},env), /recipient is not permitted/);
});

test('SMTP send recipient/host allowlists are case insensitive, but exact', () => {
  const cfg = {...base,mode:'send',username:'tester',password:'secret',from:'sender@example.net',to:'Alice@Example.Org',subject:'Test',message:'Hello'};
  const env = {ALLOW_SEND:'1',SMTP_SEND_ALLOWED_HOSTS:'MAIL.SMTP2GO.COM',SMTP_SEND_ALLOWED_RECIPIENTS:'alice@example.org'};
  assert.equal(validateRequest(cfg,env).host,'mail.smtp2go.com');
});


test('Wildcard recipient allowlist accepts explicit domains and comma-separated patterns', () => {
  const policy = ' *@Example.Org , ops@example.net , Alerts+*@Example.Net ';
  for (const address of [
    'alice@example.org','SOMEONE@EXAMPLE.ORG','ops@example.net',
    'alerts+123@example.net','alerts+@example.net',
  ]) assert.equal(recipientAllowed(address,policy),true,`Expected allowed: ${address}`);
  for (const address of [
    'stranger@example.net', 'ops@example.net.attacker.net', 'someone@example.org.evil.com',
    'someone@sub.example.org', 'report@example.net', 'nobody@outsider.example',
  ]) assert.equal(recipientAllowed(address,policy),false,`Expected denied: ${address}`);
});

test('Any public hostname can be used for SMTP sending when send host policy is unset', () => {
  const env = { ALLOW_SEND:'1', SMTP_SEND_ALLOWED_RECIPIENTS:'*@example.org, person@example.com' };
  const message = {...base, mode:'send', username:'tester', password:'secret',
    from:'from@example.com',to:'anybody@example.org',subject:'Test',message:'Hello'};
  assert.equal(validateRequest({...message,host:'mail.smtp2go.com'},env).host,'mail.smtp2go.com');
  assert.equal(validateRequest({...message,host:'smtp.office365.com'},env).host,'smtp.office365.com');
  assert.equal(validateRequest({...message,host:'other.example.net'},env).host,'other.example.net');
  assert.equal(validateRequest({...message,host:'smtp.office365.com'}, {...env,SMTP_SEND_ALLOWED_HOSTS:'*'}).host,'smtp.office365.com');
  // Existing public-target and permitted-port protections remain enforced.
  assert.throws(() => validateRequest({...message,host:'localhost'},env),/public SMTP hostname/);
  assert.throws(() => validateRequest({...message,host:'server.internal'},env),/public SMTP hostname/);
  assert.throws(() => validateRequest({...message,port:8080},env),/Port not allowed/);
  assert.throws(() => validateRequest({...message,to:'someone@unlisted.com'},env),/recipient is not permitted/);
});

test('Explicit send host policy still restricts destinations when provided', () => {
  const env = {ALLOW_SEND:'1', SMTP_SEND_ALLOWED_HOSTS:'mail.smtp2go.com,smtp.office365.com',
    SMTP_SEND_ALLOWED_RECIPIENTS:'*@example.org,person@example.com'};
  const msg = {...base,mode:'send',username:'tester',password:'secret',
    from:'sender@example.net',to:'admin@example.org',subject:'Test',message:'Hello'};
  assert.equal(validateRequest({...msg,host:'smtp.office365.com'},env).host,'smtp.office365.com');
  assert.throws(()=>validateRequest({...msg,host:'smtp.unapproved.com'},env),/SMTP host is not permitted/);
  assert.throws(()=>validateSendDeployment({...env,SMTP_SEND_ALLOWED_HOSTS:'*,mail.smtp2go.com'}),/invalid host or recipient/);
});

test('Wildcard policy is anchored to exact recipient domain (no domain suffix abuse)', () => {
  const env = {ALLOW_SEND:'1',SMTP_SEND_ALLOWED_RECIPIENTS:'*@example.com, qa+*@example.net'};
  const msg = {...base,mode:'send',username:'tester',password:'secret',from:'sender@example.net',
    to:'someone@example.com',subject:'Test',message:'Hello'};
  for (const to of ['user@example.com.evil.com','user@sub.example.com','user@notexample.com','qa+1@example.net.attacker.org']) {
    assert.throws(()=>validateRequest({...msg,to},env),/recipient is not permitted/);
  }
  assert.equal(validateRequest({...msg,to:'qa+3@example.net'},env).to,'qa+3@example.net');
});

test('Expanded private and special-use IP ranges cannot slip through as IPv6 variants',()=>{
  for (const ip of [
    '192.0.0.1','192.0.0.9','192.0.0.10','192.0.2.1','192.88.99.1',
    '2001:0db8:0:0:0:0:0:1','2001:0000::1','2001:0001:0:0:0:0:0:1',
    '2002:ac10:1:0:0:0:0:1','3fff::1', '3fff:0000:0:0::1',
  ]) assert.equal(isPublicIp(ip), false, `Special-use address should be blocked: ${ip}`);
  for(const ip of ['2606:4700:4700::1111','2a00:1450:4001::200e','2001:4860:4860::8888']) {
    assert.equal(isPublicIp(ip),true,`Legitimate public IPv6 should be accepted: ${ip}`);
  }
});
