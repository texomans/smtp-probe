import test from 'node:test';
import assert from 'node:assert/strict';
import { createAuthManager, parsePasswordMinLength } from '../src/auth.mjs';

const PASSWORD = 'a-Very-Long-Test-Only-Access-Secret-123456789';
const headers = (token, auth) => ({cookie:`${auth.cookieName}=${token}`});

test('Authentication defaults to a 15-character minimum', () => {
  assert.throws(() => createAuthManager({password:undefined}), /startup refused/);
  assert.throws(() => createAuthManager({password:'password123'}), /startup refused/);
  assert.doesNotThrow(() => createAuthManager({password:'123456789012345'}));
  assert.throws(() => createAuthManager({password:'x'.repeat(513)}), /startup refused/);
});

test('A strong password issues a revocable, expiring, HttpOnly session cookie', () => {
  let time = 100000;
  const auth = createAuthManager({password:PASSWORD,secureCookies:true,now:()=>time});
  const attempt = auth.login(PASSWORD,'198.51.100.19');
  assert.equal(attempt.status,'ok');
  assert.match(attempt.token,/^[a-zA-Z0-9_-]{43}$/);
  assert.match(attempt.csrfToken,/^[a-zA-Z0-9_-]{43}$/);
  const cookie = auth.cookie(attempt.token);
  assert.match(cookie, /HttpOnly/);
  assert.match(cookie, /__Host-smtp_probe_sid=/);
  assert.match(cookie, /SameSite=Strict/);
  assert.match(cookie, /Secure/);
  assert.match(cookie, /Max-Age=28800/);
  assert.ok(!cookie.includes(PASSWORD));
  assert.equal(auth.session(headers(attempt.token, auth))?.csrfToken,attempt.csrfToken);
  assert.equal(auth.verifyCsrf(auth.session(headers(attempt.token, auth)),attempt.csrfToken),true);
  assert.equal(auth.verifyCsrf(auth.session(headers(attempt.token, auth)),'wrong'),false);
  assert.equal(auth.session(headers('invalid-token', auth)),null);
  assert.equal(auth.session({cookie:`${auth.cookieName}=${attempt.token.substring(0,10)}`}),null);
  auth.logout(headers(attempt.token, auth));
  assert.equal(auth.session(headers(attempt.token, auth)),null);
  const renewed = auth.login(PASSWORD,'198.51.100.19');
  time += 8*60*60*1000+1;
  assert.equal(auth.session(headers(renewed.token, auth)),null);
});

test('Local private HTTP cookie mode omits Secure and logout invalidates browser cookie', () => {
  const auth=createAuthManager({password:PASSWORD,secureCookies:false});
  const successful=auth.login(PASSWORD,'127.0.0.1');
  assert.ok(!auth.cookie(successful.token).split('; ').includes('Secure'));
  assert.match(auth.clearCookie(),/Max-Age=0/);
  assert.ok(auth.session(headers(successful.token, auth)));
  auth.logout(headers(successful.token, auth));
  assert.equal(auth.session(headers(successful.token, auth)),null);
});

test('Login blocks bad guesses after 8 failures without letting attackers lock out a valid user', () => {
  let time=500000;
  const auth=createAuthManager({password:PASSWORD,now:()=>time});
  for(let i=0;i<8;i++) assert.equal(auth.login('wrong','203.0.113.1').status,'invalid');
  assert.equal(auth.login('another-wrong-guess','203.0.113.1').status,'limited');
  assert.equal(auth.login(PASSWORD,'203.0.113.1').status,'ok');
  assert.equal(auth.login(PASSWORD,'203.0.113.2').status,'ok');
  time+=15*60*1000+1;
  assert.equal(auth.login(PASSWORD,'203.0.113.1').status,'ok');
});

test('Successful login produces independent sessions and unique CSRF tokens', () => {
  const auth=createAuthManager({password:PASSWORD});
  const first=auth.login(PASSWORD,'203.0.113.1');
  const second=auth.login(PASSWORD,'203.0.113.1');
  assert.notEqual(first.token,second.token);
  assert.notEqual(first.csrfToken,second.csrfToken);
  assert.equal(auth.verifyCsrf(auth.session(headers(first.token, auth)),second.csrfToken),false);
});

test('Admin can configure a minimum of 12, 15, or 24 characters', () => {
  const memorable = 'MyPassphrase!'; // 13 Unicode code points
  assert.throws(() => createAuthManager({password:memorable}), /between 15 and 512/);
  assert.throws(() => createAuthManager({password:memorable,passwordMinLength:24}), /between 24 and 512/);
  assert.equal(createAuthManager({password:memorable,passwordMinLength:'12'}).login(memorable).status,'ok');
  assert.equal(createAuthManager({password:'x'.repeat(15),passwordMinLength:'15'}).login('x'.repeat(15)).status,'ok');
  assert.equal(createAuthManager({password:'x'.repeat(24),passwordMinLength:24}).login('x'.repeat(24)).status,'ok');
});

test('Configurable minimum accepts 1..512 and rejects malformed/out of range values', () => {
  assert.equal(parsePasswordMinLength(),15);
  assert.equal(parsePasswordMinLength('1'),1);
  assert.equal(parsePasswordMinLength('512'),512);
  for (const input of ['', '0', '-1', '12.5', 'NaN', 'abc', '15chars', ' 15', '15 ', '0512', '513', '9007199254740992']) {
    assert.throws(() => parsePasswordMinLength(input), /SMTP_PROBE_PASSWORD_MIN_LENGTH.*startup refused/i, `Rejected: ${JSON.stringify(input)}`);
  }
  assert.throws(() => createAuthManager({password:'x'.repeat(513),passwordMinLength:1}), /startup refused/);
  assert.equal(createAuthManager({password:'x',passwordMinLength:1}).login('x').status,'ok');
  assert.equal(createAuthManager({password:'x'.repeat(512),passwordMinLength:512}).login('x'.repeat(512)).status,'ok');
});

test('Password validation and subsequent login count Unicode code points consistently', () => {
  const pass = '🪪'.repeat(15);
  assert.equal(Array.from(pass).length,15);
  assert.equal(createAuthManager({password:pass}).login(pass).status,'ok');
  assert.throws(() => createAuthManager({password:'🪪'.repeat(14)}), /between 15 and 512/);
  assert.equal(createAuthManager({password:'🪪'.repeat(512),passwordMinLength:512}).login('🪪'.repeat(512)).status,'ok');
});
