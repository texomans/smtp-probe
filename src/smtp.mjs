import net from 'node:net';
import tls from 'node:tls';
import { createHmac, randomBytes } from 'node:crypto';
import { redact } from './safety.mjs';
import { gradeConnection } from './grading.mjs';

const GREETING_TIMEOUT_MS = 12000;
const IO_TIMEOUT_MS = 12000;
const CONNECT_TIMEOUT_MS = 9000;
const TLS_TIMEOUT_MS = 12000;
const MAX_RESPONSE_BYTES = 65536;

export class SMTPError extends Error {
  constructor(message, code = null, stage = null) {
    super(message); this.name = 'SMTPError'; this.smtpCode = code; this.stage = stage;
  }
}

class ResponseReader {
  constructor(socket) {
    this.socket = socket;
    this.buffer = '';
    this.lines = [];
    this.replies = [];
    this.waiters = [];
    this.error = null;
    this.bytes = 0;
    this.onData = chunk => this.receive(chunk);
    this.onError = error => this.fail(error);
    this.onClose = () => this.fail(new SMTPError('SMTP server closed the connection.'));
    socket.on('data', this.onData);
    socket.on('error', this.onError);
    socket.on('close', this.onClose);
  }
  receive(chunk) {
    this.bytes += chunk.length;
    if (this.bytes > MAX_RESPONSE_BYTES) { this.fail(new SMTPError('SMTP response exceeded safety limit.')); this.socket.destroy(); return; }
    this.buffer += chunk.toString('utf8');
    let at;
    while ((at = this.buffer.indexOf('\n')) >= 0) {
      const line = this.buffer.slice(0, at).replace(/\r$/, '');
      this.buffer = this.buffer.slice(at + 1);
      const match = /^(\d{3})([- ])(.*)$/.exec(line);
      if (!match) { this.fail(new SMTPError('Malformed SMTP response.')); this.socket.destroy(); return; }
      this.lines.push(line);
      if (this.lines.length > 100) { this.fail(new SMTPError('Too many SMTP response lines.')); this.socket.destroy(); return; }
      if (match[2] === ' ') {
        const response = { code: Number(match[1]), lines: this.lines };
        this.lines = [];
        this.bytes = 0;
        if (this.waiters.length) this.waiters.shift().resolve(response);
        else {
          this.replies.push(response);
          if (this.replies.length > 8) {this.fail(new SMTPError('Unsolicited SMTP responses exceeded safety limit.')); this.socket.destroy(); return;}
        }
      }
    }
  }
  fail(error) {
    if (this.error) return;
    this.error = error;
    for (const waiter of this.waiters.splice(0)) waiter.reject(error);
  }
  read(timeout = IO_TIMEOUT_MS) {
    if (this.error) return Promise.reject(this.error);
    if (this.replies.length) return Promise.resolve(this.replies.shift());
    return new Promise((resolve, reject) => {
      const waiter = {resolve: result => {clearTimeout(timer); resolve(result);}, reject: err => {clearTimeout(timer); reject(err);} };
      const timer = setTimeout(() => {
        const index = this.waiters.indexOf(waiter);
        if (index >= 0) this.waiters.splice(index, 1);
        reject(new SMTPError('Timed out waiting for SMTP server response.'));
      }, timeout);
      this.waiters.push(waiter);
    });
  }
  detach() {
    this.socket.off('data', this.onData);
    this.socket.off('error', this.onError);
    this.socket.off('close', this.onClose);
    if (this.waiters.length || this.buffer || this.replies.length) {
      throw new SMTPError('Unexpected pending SMTP response during TLS negotiation.');
    }
  }
}

function connectTcp(target, port) {
  return new Promise((resolve, reject) => {
    const socket = net.connect({host: target.address, family: target.family, port});
    let settled = false;
    const timer = setTimeout(() => { if (!settled) {settled = true; socket.destroy(); reject(new SMTPError('TCP connection timed out.'));} }, CONNECT_TIMEOUT_MS);
    socket.once('connect', () => {
      if (settled) return;
      settled = true; clearTimeout(timer); socket.off('error', onError);
      socket.setNoDelay(true);
      resolve(socket);
    });
    function onError(e) {
      if (settled) return;
      settled = true; clearTimeout(timer); reject(new SMTPError(`TCP connection failed (${e.code || e.message}).`));
    }
    socket.once('error', onError);
  });
}

function inspectTls(socket) {
  const certificate = socket.getPeerCertificate(true);
  const chain = [];
  const seen = new Set();
  let p = certificate;
  while (p && Object.keys(p).length && chain.length < 5) {
    if (seen.has(p.fingerprint256)) break;
    seen.add(p.fingerprint256);
    chain.push({subject: p.subject?.CN || null, issuer: p.issuer?.CN || null, expires: p.valid_to || null, fingerprint256: p.fingerprint256 || null});
    if (p.issuerCertificate === p) break;
    p = p.issuerCertificate;
  }
  return { protocol: socket.getProtocol(), cipher: socket.getCipher()?.name || null, authorized: socket.authorized, certificateChain: chain };
}

function upgradeTls(socket, host) {
  return new Promise((resolve, reject) => {
    const secure = tls.connect({socket, servername: host, rejectUnauthorized: true, minVersion: 'TLSv1.2'});
    let finished = false;
    const timer = setTimeout(() => {if (!finished) {finished = true;secure.destroy();reject(new SMTPError('TLS negotiation timed out.'));}}, TLS_TIMEOUT_MS);
    function fail(err) {
      if (finished) return;
      finished = true; clearTimeout(timer);
      secure.destroy();
      reject(new SMTPError(`TLS negotiation failed: ${err.code || err.message}`));
    }
    secure.once('error', fail);
    secure.once('secureConnect', () => {
      if (finished) return;
      finished = true; clearTimeout(timer);secure.off('error', fail);
      resolve({socket: secure, details: inspectTls(secure)});
    });
  });
}

function makeEmail(config) {
  const messageId = `${randomBytes(12).toString('hex')}@smtp-probe.local`;
  const encodedSubject = /[^\x20-\x7E]/.test(config.subject)
    ? `=?UTF-8?B?${Buffer.from(config.subject).toString('base64')}?=` : config.subject;
  // Base64 MIME content avoids injecting mail headers, dot-stuffing and 8BITMIME assumptions.
  const content = Buffer.from(config.message, 'utf8').toString('base64');
  const encodedLines = content.match(/.{1,76}/g) || [];
  const result = [
    `From: <${config.from}>`, `To: <${config.to}>`, `Subject: ${encodedSubject}`,
    `Date: ${new Date().toUTCString()}`, `Message-ID: <${messageId}>`,
    'MIME-Version: 1.0', 'Content-Type: text/plain; charset=UTF-8',
    'Content-Transfer-Encoding: base64', 'X-Mailer: SMTP Probe (diagnostic)',
    '', ...encodedLines,
  ].join('\r\n');
  return { data: result, messageId };
}

function parseAuthMechanisms(lines) {
  const parts = lines.map(l => l.slice(4).trim());
  const auth = parts.find(l => /^AUTH(?:\s|=)/i.test(l));
  return auth ? auth.replace(/^AUTH[=\s]*/i, '').split(/\s+/).map(x => x.toUpperCase()).filter(Boolean) : [];
}
function hasCapability(lines, capability) {
  return lines.some(l => new RegExp(`^${capability}(?:\\s|$)`, 'i').test(l.slice(4).trim()));
}

export async function runSmtpTest(config, target, emit, signal) {
  let socket;
  let reader;
  let stage = 'connect';
  let tlsInfo = null;
  let capabilities = [];
  const evidence = {};
  const finish = result => ({...result, grading:gradeConnection(config, result, evidence)});
  const authBlob = config.username && config.password ? Buffer.from(`\0${config.username}\0${config.password}`).toString('base64') : '';
  const secrets = [config.username, config.password, authBlob];
  const record = (kind, detail) => emit({type: 'transcript', kind, text: redact(detail, secrets), time: new Date().toISOString()});
  const stageEvent = (next, detail) => {stage = next; emit({type: 'stage', name: next, text: detail});};
  const onAbort = () => {if (socket) socket.destroy(new SMTPError('Connection cancelled or exceeded overall time limit.'));};
  if (signal) signal.addEventListener('abort', onAbort, {once:true});
  function ensureResponse(reply, allowed, description) {
    if (!allowed.includes(reply.code)) throw new SMTPError(`${description}: ${reply.lines.at(-1).slice(4)}`, reply.code, stage);
  }
  async function response() {
    const reply = await reader.read(GREETING_TIMEOUT_MS);
    for (const l of reply.lines) record('server', `S: ${l}`);
    return reply;
  }
  async function command(text, {display = text, allow = [250], description = text.split(' ')[0]} = {}) {
    record('client', `C: ${display}`);
    reader.socket.write(`${text}\r\n`);
    const reply = await response();
    ensureResponse(reply, allow, description);
    return reply;
  }
  try {
    stageEvent('connect', `Connecting to ${config.host}:${config.port} (${target.address})`);
    record('info', `Target: ${config.host}:${config.port}, resolved IP: ${target.address}`);
    socket = await connectTcp(target, config.port);
    evidence.tcp = 'pass';
    reader = new ResponseReader(socket);
    if (config.tlsMode === 'implicit') {
      stageEvent('tls', 'Negotiating implicit TLS');
      reader.detach();
      const upgraded = await upgradeTls(socket, config.host);
      socket = upgraded.socket; tlsInfo = upgraded.details; evidence.tls = 'pass';
      reader = new ResponseReader(socket);
      record('tls', `TLS established: ${tlsInfo.protocol} · ${tlsInfo.cipher} · certificate verified`);
    }
    stageEvent('greeting', 'Reading SMTP banner');
    ensureResponse(await response(), [220], 'SMTP banner');
    evidence.greeting = 'pass';
    stageEvent('ehlo', 'Inspecting SMTP capabilities');
    let ehlo = await command('EHLO smtp-probe.local', {description:'EHLO'});
    capabilities = ehlo.lines.map(x => redact(x.slice(4), secrets));
    evidence.ehlo = 'pass';
    if (!tlsInfo) {
      evidence.starttls = config.tlsMode === 'starttls' ? hasCapability(ehlo.lines, 'STARTTLS') : undefined;
      evidence.plaintextAuth = parseAuthMechanisms(ehlo.lines).length > 0;
    }
    if (config.tlsMode === 'starttls') {
      if (!hasCapability(ehlo.lines, 'STARTTLS')) throw new SMTPError('STARTTLS is not advertised; refusing to continue without encryption.', null, stage);
      stageEvent('tls', 'Upgrading with STARTTLS');
      await command('STARTTLS', {allow:[220], description:'STARTTLS'});
      reader.detach();
      const upgraded = await upgradeTls(socket, config.host);
      socket = upgraded.socket; tlsInfo = upgraded.details; evidence.tls = 'pass';
      reader = new ResponseReader(socket);
      record('tls', `TLS established: ${tlsInfo.protocol} · ${tlsInfo.cipher} · certificate verified`);
      stageEvent('ehlo', 'Rechecking SMTP capabilities after STARTTLS');
      // RFC 3207: pre-TLS capabilities MUST be discarded and EHLO repeated.
      evidence.ehlo = 'not-tested';
      capabilities = [];
      ehlo = await command('EHLO smtp-probe.local');
      evidence.ehlo = 'pass';
      capabilities = ehlo.lines.map(x => redact(x.slice(4), secrets));
    }
    if (config.username) {
      if (!tlsInfo) throw new SMTPError('Refusing to send credentials without TLS.', null, stage);
      stageEvent('auth', 'Authenticating over TLS');
      const offered = parseAuthMechanisms(ehlo.lines);
      let mechanism = config.authMethod;
      if (mechanism === 'auto') mechanism = ['PLAIN', 'LOGIN', 'CRAM-MD5'].find(x => offered.includes(x))?.toLowerCase() || '';
      if (!mechanism || !offered.includes(mechanism.toUpperCase())) throw new SMTPError(`Requested authentication mechanism unavailable. Server advertises: ${offered.join(', ') || '(none)'}.`, null, stage);
      if (mechanism === 'plain') {
        const auth = Buffer.from(`\0${config.username}\0${config.password}`).toString('base64');
        await command(`AUTH PLAIN ${auth}`, {display:'AUTH PLAIN [REDACTED]', allow:[235], description:'AUTH PLAIN'});
      } else if (mechanism === 'login') {
        await command('AUTH LOGIN', {allow:[334], description:'AUTH LOGIN'});
        await command(Buffer.from(config.username).toString('base64'), {display:'[REDACTED USERNAME]', allow:[334], description:'AUTH LOGIN username'});
        await command(Buffer.from(config.password).toString('base64'), {display:'[REDACTED PASSWORD]', allow:[235], description:'AUTH LOGIN password'});
      } else if (mechanism === 'cram-md5') {
        const challengeReply = await command('AUTH CRAM-MD5', {allow:[334], description:'AUTH CRAM-MD5'});
        const challenge = Buffer.from(challengeReply.lines.at(-1).slice(4).trim(), 'base64');
        const mac = createHmac('md5', config.password).update(challenge).digest('hex');
        const answer = Buffer.from(`${config.username} ${mac}`).toString('base64');
        await command(answer, {display:'[REDACTED AUTH RESPONSE]', allow:[235], description:'AUTH CRAM-MD5 challenge'});
      }
      evidence.auth = 'pass';
      record('info', `Authentication succeeded (${mechanism.toUpperCase()})`);
    }
    if (config.mode === 'send') {
      stageEvent('send', 'Submitting one test email');
      await command(`MAIL FROM:<${config.from}>`, {allow:[250], description:'MAIL FROM'});
      const recipientReply = await command(`RCPT TO:<${config.to}>`, {allow:[250,251], description:'RCPT TO'});
      await command('DATA', {allow:[354], description:'DATA'});
      const {data, messageId} = makeEmail(config);
      record('client', `C: [message data redacted: ${Buffer.byteLength(data)} bytes]`);
      reader.socket.write(`${data}\r\n.\r\n`);
      const accepted = await response();
      ensureResponse(accepted, [250], 'Message submission');
      stageEvent('complete', 'SMTP server accepted the message for delivery');
      evidence.submission = 'pass';
      return finish({
        ok:true,
        message:'SMTP server accepted the test email for delivery (inbox delivery not yet confirmed).',
        messageId,
        delivery: {
          recipient: config.to,
          recipientCode: recipientReply.code,
          smtpCode: accepted.code,
          smtpResponse: redact(accepted.lines.at(-1).slice(4), secrets),
        },
        tls:tlsInfo,
        capabilities,
      });
    }
    stageEvent('complete', config.username ? 'SMTP credentials verified' : 'SMTP server capabilities inspected');
    return finish({ok:true, message:config.username ? 'SMTP connection, TLS, and credentials verified.' : 'SMTP connection and capabilities verified (no authentication attempted).', tls:tlsInfo, capabilities});
  } catch (err) {
    const failedCheck = {connect:'tcp',greeting:'greeting',ehlo:'ehlo',tls:'tls',auth:'auth',send:'submission'}[stage];
    if (failedCheck && evidence[failedCheck] !== 'pass') evidence[failedCheck] = 'fail';
    const message = redact(err.message || String(err), secrets);
    record('error', `ERROR: ${message}`);
    return finish({ok:false, message, smtpCode:err.smtpCode || null, stage:err.stage || stage, tls:tlsInfo, capabilities});
  } finally {
    if (signal) signal.removeEventListener('abort', onAbort);
    if (socket && !socket.destroyed) {
      // Send QUIT without waiting; this is diagnostic cleanup, not a second authentication.
      try {socket.write('QUIT\r\n'); record('client', 'C: QUIT');} catch { /* ignore */ }
      socket.end();
      const s = socket;
      setTimeout(() => {if (!s.destroyed) s.destroy();}, 250).unref();
    }
  }
}
