import http from 'node:http';
import net from 'node:net';
import { createTestLimiter } from './rate-limit.mjs';
import { readFile } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { InputError, validateRequest, resolvePublicTarget, validateSendDeployment } from './safety.mjs';
import { runSmtpTest } from './smtp.mjs';
import { createAuthManager, parsePasswordMinLength } from './auth.mjs';

const APP_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '0.0.0.0';
const ACCESS_PASSWORD = process.env.SMTP_PROBE_PASSWORD;
const PASSWORD_MIN_SETTING = process.env.SMTP_PROBE_PASSWORD_MIN_LENGTH || '15';
const COOKIE_SECURE_SETTING = process.env.SMTP_PROBE_COOKIE_SECURE ?? '1';
const REQUEST_TIMEOUT_MS = 45000;
const MAX_REQUEST_BYTES = 16000;
const MAX_ACTIVE = 3;
if (process.env.PUBLIC_ORIGIN && !/^https:\/\/[^\s/]+$/.test(process.env.PUBLIC_ORIGIN)) {
  throw new Error('PUBLIC_ORIGIN must be an HTTPS origin (no trailing slash).');
}
if (process.env.PUBLIC_ORIGIN && COOKIE_SECURE_SETTING === '0') {
  throw new Error('SMTP_PROBE_COOKIE_SECURE=0 is not allowed when PUBLIC_ORIGIN is configured.');
}
const APP_VERSION = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version;
const PASSWORD_MIN_LENGTH = parsePasswordMinLength(PASSWORD_MIN_SETTING);
if (PASSWORD_MIN_LENGTH < 15) {
  console.warn(`Warning: SMTP_PROBE_PASSWORD_MIN_LENGTH=${PASSWORD_MIN_LENGTH} is below the recommended 15 characters for password-only Internet access.`);
}
validateSendDeployment();
const auth = createAuthManager({
  password: ACCESS_PASSWORD,
  passwordMinLength: PASSWORD_MIN_LENGTH,
  secureCookies: COOKIE_SECURE_SETTING !== '0',
});
const testLimiter = createTestLimiter();
let active = 0;

const responseHeaders = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Cache-Control': 'no-store',
  'Content-Security-Policy': "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'none'",
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  ...(process.env.PUBLIC_ORIGIN ? {'Strict-Transport-Security':'max-age=31536000'} : {}),
};
function json(res, code, data, extra = {}) {
  res.writeHead(code, {...responseHeaders, 'Content-Type':'application/json; charset=utf-8', ...extra});
  res.end(JSON.stringify(data));
}
function requesterIp(req) {
  if (process.env.TRUST_PROXY === '1') {
    const forwarded = req.headers['x-forwarded-for'];
    if (typeof forwarded === 'string') {
      // NPM must append the observed client IP. The leftmost XFF entry can be spoofed.
      const candidate = forwarded.split(',').at(-1)?.trim();
      if (candidate && net.isIP(candidate)) return candidate;
    }
  }
  return req.socket.remoteAddress || 'unknown';
}
function checkOrigin(req) {
  if (req.headers['sec-fetch-site'] === 'cross-site') return false;
  const origin = req.headers.origin;
  if (!origin) return true;
  try {
    const parsedOrigin = new URL(origin);
    if (!['https:', 'http:'].includes(parsedOrigin.protocol)) return false;
    if (process.env.PUBLIC_ORIGIN) return parsedOrigin.origin === process.env.PUBLIC_ORIGIN;
    const destHost = String(req.headers.host || '').trim();
    return Boolean(destHost) && parsedOrigin.host === destHost;
  } catch {return false;}
}
async function readJsonBody(req, maxBytes = MAX_REQUEST_BYTES) {
  let length = 0;
  const chunks = [];
  for await (const chunk of req) {
    length += chunk.length;
    if (length > maxBytes) throw new InputError('Request too large.');
    chunks.push(chunk);
  }
  try {return JSON.parse(Buffer.concat(chunks).toString('utf8'));}
  catch {throw new InputError('Malformed JSON request.');}
}
async function serveFile(res, filename, type) {
  try {
    const source = await readFile(path.join(APP_DIR, 'public', filename));
    const buffer = filename.endsWith('.html')
      ? Buffer.from(source.toString('utf8').replaceAll('__SMTP_PROBE_VERSION__', APP_VERSION))
      : source;
    res.writeHead(200, {...responseHeaders, 'Content-Type':type, 'Content-Length':buffer.length});
    res.end(buffer);
  } catch {json(res, 404, {error:'Asset not found.'});}
}
async function apiTest(req, res, session) {
  if (!session) return json(res,401,{error:'Authentication required.'});
  if (!auth.verifyCsrf(session, req.headers['x-csrf-token'])) return json(res,403,{error:'Session verification failed. Refresh and retry.'});
  if (!checkOrigin(req)) return json(res,403,{error:'Cross-origin request blocked.'});
  if (!String(req.headers['content-type'] || '').toLowerCase().startsWith('application/json')) return json(res,415,{error:'Expected application/json.'});
  if (active >= MAX_ACTIVE) return json(res,429,{error:'Server busy. Retry shortly.'});
  const ip = requesterIp(req);
  let config, target;
  try {
    const body = await readJsonBody(req);
    config = validateRequest(body);
    if (!testLimiter.allow({ ip, host: config.host, username: config.username, mode: config.mode })) return json(res,429,{error:'Test limit reached for this client, SMTP host, or account. Try again later.'});
    target = await resolvePublicTarget(config.host);
  } catch (error) {
    const code = error instanceof InputError ? 400 : 502;
    return json(res,code,{error: error instanceof InputError ? error.message : 'DNS lookup failed. Check hostname or server DNS.'});
  }
  active++;
  const controller = new AbortController();
  const overall = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  const cancelOnClose = () => controller.abort();
  res.on('close', cancelOnClose);
  res.writeHead(200, {
    ...responseHeaders,
    'Content-Type':'text/event-stream; charset=utf-8',
    'Connection':'keep-alive',
    'X-Accel-Buffering':'no'
  });
  res.flushHeaders?.();
  const started = Date.now();
  function emit(event) {
    if (!res.destroyed && !res.writableEnded) res.write(`data: ${JSON.stringify(event)}\n\n`);
  }
  try {
    emit({type:'stage', name:'start', text:`Starting ${config.mode === 'send' ? 'SMTP send test' : 'SMTP connection test'}`});
    const result = await runSmtpTest(config,target,emit,controller.signal);
    emit({type:'result', ...result, durationMs:Date.now()-started});
  } catch {
    emit({type:'result', ok:false, message:'Unexpected server error while performing test.'});
  } finally {
    clearTimeout(overall);
    res.off('close',cancelOnClose);
    active--;
    if (!res.destroyed) res.end();
  }
}
async function login(req, res) {
  if (!checkOrigin(req)) return json(res,403,{error:'Cross-origin request blocked.'});
  if (!String(req.headers['content-type'] || '').toLowerCase().startsWith('application/json')) return json(res,415,{error:'Expected application/json.'});
  let body;
  try { body = await readJsonBody(req, 2048); }
  catch (error) { return json(res,400,{error:error instanceof InputError ? error.message : 'Invalid request.'}); }
  if (!body || typeof body !== 'object' || Array.isArray(body) || typeof body.password !== 'string') {
    return json(res,400,{error:'A password is required.'});
  }
  const outcome = auth.login(body.password, requesterIp(req));
  if (outcome.status === 'limited') return json(res,429,{error:'Too many attempts. Try again in 15 minutes.'},{'Retry-After':'900'});
  if (outcome.status === 'invalid') return json(res,401,{error:'Incorrect access password.'});
  return json(res,200,{ok:true,csrfToken:outcome.csrfToken,expiresAt:outcome.expiresAt},
    {'Set-Cookie':auth.cookie(outcome.token)});
}
function logout(req,res,session) {
  if (!session) return json(res,401,{error:'Authentication required.'});
  if (!checkOrigin(req)) return json(res,403,{error:'Cross-origin request blocked.'});
  if (!auth.verifyCsrf(session, req.headers['x-csrf-token'])) return json(res,403,{error:'Session verification failed.'});
  auth.logout(req.headers);
  return json(res,200,{ok:true},{'Set-Cookie':auth.clearCookie()});
}
const server = http.createServer(async (req,res) => {
  try {
    const url = new URL(req.url || '/', 'http://localhost');
    const session = auth.session(req.headers);
    if (req.method === 'GET' && url.pathname === '/') {
      return await serveFile(res, session ? 'index.html' : 'login.html','text/html; charset=utf-8');
    }
    if (req.method === 'GET' && url.pathname === '/app.css') return await serveFile(res,'app.css','text/css; charset=utf-8');
    if (req.method === 'GET' && url.pathname === '/login.js') return await serveFile(res,'login.js','text/javascript; charset=utf-8');
    if (req.method === 'GET' && url.pathname === '/app.js') {
      if (!session) return json(res,401,{error:'Authentication required.'});
      return await serveFile(res,'app.js','text/javascript; charset=utf-8');
    }
    if (req.method === 'GET' && url.pathname === '/healthz') return json(res,200,{status:'ok'});
    if (req.method === 'GET' && url.pathname === '/api/session') {
      return json(res,200,session ? {authenticated:true,csrfToken:session.csrfToken,expiresAt:session.expiresAt} : {authenticated:false});
    }
    if (req.method === 'POST' && url.pathname === '/api/login') return await login(req,res);
    if (req.method === 'POST' && url.pathname === '/api/logout') return logout(req,res,session);
    if (req.method === 'GET' && url.pathname === '/api/info') {
      if (!session) return json(res,401,{error:'Authentication required.'});
      return json(res,200,{name:'SMTP Probe',version:APP_VERSION,sendEnabled:process.env.ALLOW_SEND === '1'});
    }
    if (req.method === 'POST' && url.pathname === '/api/test') return await apiTest(req,res,session);
    return json(res,404,{error:'Not found.'});
  } catch {
    if (!res.headersSent) return json(res,500,{error:'Internal server error.'});
    res.end();
  }
});
server.requestTimeout = 20000;
server.headersTimeout = 10000;
server.keepAliveTimeout = 5000;
server.listen(PORT, HOST, () => console.log(`SMTP Probe v${APP_VERSION} listening on ${HOST}:${PORT} (send enabled: ${process.env.ALLOW_SEND === '1'})`));
