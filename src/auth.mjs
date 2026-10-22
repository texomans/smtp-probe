import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

export const SESSION_COOKIE = 'smtp_probe_sid';
export const HOST_SESSION_COOKIE = '__Host-smtp_probe_sid';
const SESSION_MS = 8 * 60 * 60 * 1000;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const MAX_PER_IP = 8;
const MAX_GLOBAL = 80;
const MAX_SESSIONS = 128;
const MAX_RATE_KEYS = 2048;

function hash(value) {
  return createHash('sha256').update(value).digest();
}
function hashKey(value) {
  return hash(value).toString('hex');
}
function readCookie(headers, cookieName) {
  const all = headers?.cookie;
  if (typeof all !== 'string') return null;
  for (const pair of all.split(';')) {
    const [name, ...values] = pair.trim().split('=');
    const value = values.join('=');
    if (name === cookieName && /^[a-zA-Z0-9_-]{43}$/.test(value)) return value;
  }
  return null;
}
function safeEquals(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}

export const DEFAULT_PASSWORD_MIN_LENGTH = 15;
export const MAX_PASSWORD_LENGTH = 512;

/** An administrator may deliberately override the default minimum (1–512). */
export function parsePasswordMinLength(raw = DEFAULT_PASSWORD_MIN_LENGTH) {
  const value = String(raw);
  if (!/^[1-9][0-9]*$/.test(value)) {
    throw new Error('SMTP_PROBE_PASSWORD_MIN_LENGTH must be a whole number between 1 and 512. Application startup refused.');
  }
  const length = Number(value);
  if (!Number.isSafeInteger(length) || length > MAX_PASSWORD_LENGTH) {
    throw new Error('SMTP_PROBE_PASSWORD_MIN_LENGTH must be a whole number between 1 and 512. Application startup refused.');
  }
  return length;
}

export function createAuthManager({ password, passwordMinLength = DEFAULT_PASSWORD_MIN_LENGTH, secureCookies = true, now = Date.now } = {}) {
  const minimum = parsePasswordMinLength(passwordMinLength);
  // Count Unicode code points so a valid multi-byte passphrase can be used to log in.
  const characters = typeof password === 'string' ? Array.from(password).length : 0;
  if (characters < minimum || characters > MAX_PASSWORD_LENGTH) {
    throw new Error(`SMTP_PROBE_PASSWORD must be between ${minimum} and ${MAX_PASSWORD_LENGTH} characters (SMTP_PROBE_PASSWORD_MIN_LENGTH=${minimum}). Application startup refused.`);
  }
  const cookieName = secureCookies ? HOST_SESSION_COOKIE : SESSION_COOKIE;
  const expected = hash(password);
  const sessions = new Map();
  const attempts = new Map();

  function prune() {
    const current = now();
    for (const [key, value] of sessions) if (value.expiresAt <= current) sessions.delete(key);
    for (const [key, stamps] of attempts) {
      const recent = stamps.filter(t => current - t < LOGIN_WINDOW_MS);
      if (recent.length) attempts.set(key, recent);
      else attempts.delete(key);
    }
    while (attempts.size > MAX_RATE_KEYS) attempts.delete(attempts.keys().next().value);
  }
  function isLimited(ip) {
    prune();
    return (attempts.get(`ip:${ip}`)?.length ?? 0) >= MAX_PER_IP ||
           (attempts.get('global')?.length ?? 0) >= MAX_GLOBAL;
  }
  function failedAttempt(ip) {
    for (const key of [`ip:${ip}`, 'global']) {
      const values = attempts.get(key) ?? [];
      values.push(now());
      attempts.set(key, values);
    }
    while (attempts.size > MAX_RATE_KEYS) attempts.delete(attempts.keys().next().value);
  }
  function login(candidate, ip = 'unknown') {
    const limited = isLimited(ip);
    const validCandidate = typeof candidate === 'string' && Array.from(candidate).length <= MAX_PASSWORD_LENGTH;
    const provided = hash(validCandidate ? candidate : '');
    if (!validCandidate || !timingSafeEqual(provided, expected)) {
      if (limited) return { status: 'limited' };
      failedAttempt(ip);
      return { status: 'invalid' };
    }
    // A bad actor must not lock out a technician who knows the real secret.
    // Wrong guesses are still limited; the password must be high entropy.
    attempts.delete(`ip:${ip}`);
    prune();
    while (sessions.size >= MAX_SESSIONS) sessions.delete(sessions.keys().next().value);
    const token = randomBytes(32).toString('base64url');
    const entry = { csrfToken: randomBytes(32).toString('base64url'), expiresAt: now() + SESSION_MS };
    sessions.set(hashKey(token), entry);
    return { status: 'ok', token, ...entry };
  }
  function session(headers) {
    const token = readCookie(headers, cookieName);
    if (!token) return null;
    const key = hashKey(token);
    const entry = sessions.get(key);
    if (!entry) return null;
    if (entry.expiresAt <= now()) { sessions.delete(key); return null; }
    return entry;
  }
  function verifyCsrf(entry, header) {
    return Boolean(entry && safeEquals(entry.csrfToken, header));
  }
  function logout(headers) {
    const token = readCookie(headers, cookieName);
    if (token) sessions.delete(hashKey(token));
  }
  function cookie(token) {
    return [
      `${cookieName}=${token}`,
      'HttpOnly',
      'SameSite=Strict',
      'Path=/',
      `Max-Age=${Math.floor(SESSION_MS / 1000)}`,
      ...(secureCookies ? ['Secure'] : []),
    ].join('; ');
  }
  function clearCookie() {
    return [
      `${cookieName}=`, 'HttpOnly', 'SameSite=Strict', 'Path=/', 'Max-Age=0',
      ...(secureCookies ? ['Secure'] : []),
    ].join('; ');
  }
  return { login, session, verifyCsrf, logout, cookie, clearCookie, prune, cookieName };
}
