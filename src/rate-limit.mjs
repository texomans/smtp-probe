import { createHash } from 'node:crypto';

// Limits protect external SMTP services, not just this UI. No usernames or
// passwords are stored as plaintext in the limiter's keys.
const POLICY = Object.freeze({
  dns: { perIp: 6, perIpMs: 5 * 60_000, perHost: 40, perHostMs: 15 * 60_000,
    perIdentity: 0, perIdentityMs: 15 * 60_000, global: 100, globalMs: 60 * 60_000 },
  verify: { perIp: 8, perIpMs: 5 * 60_000, perHost: 60, perHostMs: 15 * 60_000,
    perIdentity: 12, perIdentityMs: 15 * 60_000, global: 150, globalMs: 60 * 60_000 },
  send: { perIp: 3, perIpMs: 10 * 60_000, perHost: 12, perHostMs: 60 * 60_000,
    perIdentity: 6, perIdentityMs: 60 * 60_000, global: 20, globalMs: 60 * 60_000 },
});
const MAX_KEYS = 3500;

function keyHash(text) {
  return createHash('sha256').update(text).digest('hex');
}

// Deliberately one-instance/in-memory. A reverse proxy or shared storage is
// required for multi-replica or restart-resistant limits.
export function createTestLimiter({ now = Date.now, policy = POLICY } = {}) {
  const buckets = new Map();

  function compact(current) {
    for (const [key, bucket] of buckets) {
      bucket.hits = bucket.hits.filter(t => t > current - bucket.windowMs);
      if (bucket.hits.length === 0) buckets.delete(key);
    }
    // If too many distinct names are supplied, deny new test requests rather
    // than evicting rate-limit records (which could be abused to reset quotas).
    return buckets.size <= MAX_KEYS;
  }

  function allow({ ip, host, username = '', mode = 'verify' }) {
    const spec = policy[mode];
    if (!spec || typeof ip !== 'string' || typeof host !== 'string') return false;
    const current = now();
    if (!compact(current)) return false;
    const dest = keyHash(host.toLowerCase());
    const client = keyHash(ip);
    const checks = [
      { key: `${mode}:global`, max: spec.global, ms: spec.globalMs },
      { key: `${mode}:ip:${client}`, max: spec.perIp, ms: spec.perIpMs },
      { key: `${mode}:host:${dest}`, max: spec.perHost, ms: spec.perHostMs },
    ];
    if (username) {
      checks.push({ key: `${mode}:identity:${keyHash(`${host.toLowerCase()}\0${username}`)}`,
        max: spec.perIdentity, ms: spec.perIdentityMs });
    }
    // Check all counters before consuming any. Rejected requests do not debit
    // unrelated buckets and cannot be used to exhaust another customer's quota.
    for (const { key, max, ms } of checks) {
      const bucket = buckets.get(key);
      const recent = (bucket?.hits ?? []).filter(t => t > current - ms);
      if (recent.length >= max) return false;
    }
    const newKeys = checks.reduce((n, item) => n + (buckets.has(item.key) ? 0 : 1), 0);
    if (buckets.size + newKeys > MAX_KEYS) return false;
    for (const { key, ms } of checks) {
      const previous = buckets.get(key)?.hits ?? [];
      buckets.set(key, { hits: [...previous.filter(t => t > current - ms), current], windowMs: ms });
    }
    return true;
  }
  return { allow, compact };
}
