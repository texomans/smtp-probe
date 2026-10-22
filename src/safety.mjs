import dns from 'node:dns/promises';
import net from 'node:net';

const HOSTNAME_RE = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;
const EMAIL_RE = /^[A-Z0-9.!#$%&'*+/?^_`{|}~-]+@[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+$/i;
const DEFAULT_PORTS = '25,465,587,2525,8465,443';
// Comma-separated policy entries are administrator-defined. In v0.1.5,
// SMTP_SEND_ALLOWED_HOSTS is optional: empty or '*' means any public SMTP host,
// still subject to strict DNS/IP screening, allowed ports and rate limits.
// Recipient wildcards are deliberately limited to ONE '*' in the local part
// of a concrete mailbox domain (e.g. *@texomans.com, alerts+*@texomans.com).
// Wildcards in the domain or global '*' / '*@*' are never accepted.
function splitList(raw) {
  if (typeof raw !== 'string' || raw.length > 4000) throw new InputError('Invalid SMTP send policy configuration.');
  const values = raw.split(',').map(x => x.trim().toLowerCase()).filter(Boolean);
  if (values.length > 100) throw new InputError('SMTP send policy list is too large.');
  return values;
}

function validRecipientPattern(pattern) {
  if (typeof pattern !== 'string' || pattern.length > 254) return false;
  const parts = pattern.split('@');
  if (parts.length !== 2) return false;
  const [local, domain] = parts;
  // A wildcard MUST be in the local part, and can appear at most once.
  if (domain.includes('*') || (local.match(/\*/g) ?? []).length > 1) return false;
  // Substitute one conventional mailbox character for '*' to use our existing
  // conservative email format validation; this also enforces an exact domain.
  return EMAIL_RE.test(`${local.replace('*', 'x')}@${domain}`);
}

export function recipientAllowed(address, policy) {
  const input = String(address).toLowerCase();
  const [local, domain] = input.split('@');
  if (!local || !domain || !EMAIL_RE.test(input)) return false;
  return splitList(policy).some(entry => {
    if (!validRecipientPattern(entry)) return false;
    const [allowedLocal, allowedDomain] = entry.split('@');
    if (domain !== allowedDomain) return false;
    const wildcard = allowedLocal.indexOf('*');
    if (wildcard < 0) return local === allowedLocal;
    return local.startsWith(allowedLocal.slice(0, wildcard))
      && local.endsWith(allowedLocal.slice(wildcard + 1));
  });
}

export function validateSendDeployment(env = process.env) {
  if (env.ALLOW_SEND !== '1') return;
  const hosts = splitList(env.SMTP_SEND_ALLOWED_HOSTS ?? '');
  const recipients = splitList(env.SMTP_SEND_ALLOWED_RECIPIENTS ?? '');
  if (!recipients.length) {
    throw new InputError('ALLOW_SEND=1 requires a nonempty SMTP_SEND_ALLOWED_RECIPIENTS allowlist.');
  }
  // An omitted SMTP send host list OR a lone '*' enables all public SMTP hosts.
  // A nonempty list of concrete hostnames still supports restrictive deployments.
  if ((hosts.length && !(hosts.length === 1 && hosts[0] === '*') && hosts.some(host => !HOSTNAME_RE.test(host)))
      || recipients.some(pattern => !validRecipientPattern(pattern))) {
    throw new InputError('SMTP send allowlists contain an invalid host or recipient pattern.');
  }
}


export class InputError extends Error {
  constructor(message) { super(message); this.name = 'InputError'; }
}

function requireText(value, name, max = 250) {
  if (typeof value !== 'string' || value.length > max) throw new InputError(`Invalid ${name}.`);
  return value;
}
function validateEmail(value, name) {
  const email = requireText(value, name, 254).trim();
  if (!EMAIL_RE.test(email) || /[\r\n]/.test(email)) throw new InputError(`Enter a valid ${name}.`);
  return email;
}

export function validateRequest(input, env = process.env) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new InputError('Invalid request.');
  const host = requireText(input.host, 'SMTP host').trim().toLowerCase();
  if (!HOSTNAME_RE.test(host) || /(?:\.local|\.localhost|\.internal|\.home\.arpa|\.onion|\.invalid|\.test|\.example)$/i.test(host)) throw new InputError('Use a public SMTP hostname such as mail.smtp2go.com. IP literals and internal names are blocked.');
  // Optional administrator allowlist; exact hostnames only, not suffix matches.
  if (env.SMTP_ALLOWED_HOSTS) {
    const allowedHosts = String(env.SMTP_ALLOWED_HOSTS).toLowerCase().split(',').map(s => s.trim()).filter(Boolean);
    if (!allowedHosts.includes(host)) throw new InputError('SMTP host is not allowed by the administrator.');
  }
  const port = Number(input.port);
  const allowedPorts = String(env.SMTP_ALLOWED_PORTS || DEFAULT_PORTS).split(',').map(x => Number(x.trim()));
  if (!Number.isInteger(port) || port < 1 || port > 65535 || !allowedPorts.includes(port)) {
    throw new InputError(`Port not allowed. Enabled ports: ${allowedPorts.join(', ')}.`);
  }
  const tlsMode = input.tlsMode;
  if (!['starttls', 'implicit', 'none'].includes(tlsMode)) throw new InputError('Invalid TLS mode.');
  const mode = input.mode;
  if (!['verify', 'send'].includes(mode)) throw new InputError('Invalid test mode.');
  const username = requireText(input.username ?? '', 'username', 320);
  const password = requireText(input.password ?? '', 'password', 2048);
  const authMethod = input.authMethod || 'auto';
  if (!['auto', 'plain', 'login', 'cram-md5'].includes(authMethod)) throw new InputError('Invalid authentication method.');
  if (Boolean(username) !== Boolean(password)) throw new InputError('Provide both username and password, or leave both blank.');
  if (username && tlsMode === 'none') throw new InputError('Authentication over plaintext SMTP is blocked. Select STARTTLS or implicit TLS.');
  if (mode === 'send' && env.ALLOW_SEND !== '1') throw new InputError('Sending is disabled for this deployment.');
  if (mode === 'send') validateSendDeployment(env);
  if (mode === 'send' && (!username || tlsMode === 'none')) throw new InputError('Test sending requires encrypted, authenticated SMTP.');
  const result = { host, port, tlsMode, mode, username, password, authMethod };
  if (mode === 'send') {
    result.from = validateEmail(input.from, 'sender address');
    result.to = validateEmail(input.to, 'recipient address');
    const sendHosts = splitList(env.SMTP_SEND_ALLOWED_HOSTS ?? '');
    if (sendHosts.length && !sendHosts.includes('*') && !sendHosts.includes(host)) {
      throw new InputError('Sending to this SMTP host is not permitted by the administrator.');
    }
    if (!recipientAllowed(result.to, env.SMTP_SEND_ALLOWED_RECIPIENTS ?? '')) {
      throw new InputError('Sending to this recipient is not permitted by the administrator.');
    }
    result.subject = requireText(input.subject, 'subject', 160).trim();
    if (!result.subject || /[\r\n]/.test(result.subject)) throw new InputError('Subject must be nonempty and contain no newlines.');
    result.message = requireText(input.message, 'body', 8000);
    if (!result.message.trim()) throw new InputError('Message body is required.');
  }
  return result;
}

function isPublicIpv4(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(x => !Number.isInteger(x) || x < 0 || x > 255)) return false;
  const [a, b, c] = parts;
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && (b === 168 || b === 0 || (b === 88 && c === 99))) return false;
  if (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) return false;
  if (a === 203 && b === 0 && c === 113) return false;
  if (a === 192 && b === 0 && c === 2) return false;

  if (a === 255) return false;
  return true;
}

// Normalize valid IPv6 addresses so leading zeros and compressed notation cannot
// bypass the special-purpose prefix checks. IPv4-embedded forms are blocked.
function ipv6Words(ip) {
  if (net.isIP(ip) !== 6 || ip.includes('.') || ip.includes('%')) return null;
  const halves = ip.toLowerCase().split('::');
  if (halves.length > 2) return null;
  const before = halves[0] ? halves[0].split(':') : [];
  const after = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const count = before.length + after.length;
  const words = halves.length === 2
    ? [...before, ...Array(8 - count).fill('0'), ...after]
    : before;
  if (words.length !== 8) return null;
  return words.map(x => Number.parseInt(x, 16));
}
function prefix6(words, prefix, mask) {
  const value = words.reduce((acc, word) => (acc << 16n) | BigInt(word), 0n);
  const bits = BigInt(mask);
  return (value >> (128n - bits)) === (BigInt(prefix) >> (128n - bits));
}
export function isPublicIp(ip) {
  const family = net.isIP(ip);
  if (family === 4) return isPublicIpv4(ip);
  if (family !== 6) return false;
  const words = ipv6Words(ip);
  if (!words) return false;
  // Constrain to 2000::/3 globally routable space, then deny known
  // documentation, translation, protocol-assignment and special-use blocks.
  if (words[0] < 0x2000 || words[0] > 0x3fff) return false;
  if (prefix6(words, 0x20010000000000000000000000000000n, 23)) return false; // IETF protocol assignments
  if (prefix6(words, 0x20010db8000000000000000000000000n, 32)) return false; // RFC 3849 documentation
  if (prefix6(words, 0x20020000000000000000000000000000n, 16)) return false; // 6to4 encapsulation
  if (prefix6(words, 0x3fff0000000000000000000000000000n, 20)) return false; // RFC 9637 documentation
  return true;
}

export async function resolvePublicTarget(host, lookup = dns.lookup) {
  const answers = await lookup(host, { all: true, verbatim: true });
  if (!Array.isArray(answers) || answers.length === 0) throw new InputError('SMTP hostname did not resolve.');
  if (answers.some(answer => !isPublicIp(answer.address))) {
    throw new InputError('SMTP hostname resolves to a private, reserved, or mixed public/private address. Connection blocked.');
  }
  const candidate = answers.find(answer => answer.family === 4) ?? answers[0];
  return { address: candidate.address, family: candidate.family, host };
}

export function redact(value, secrets = []) {
  let text = String(value);
  for (const s of secrets) {
    if (!s) continue;
    text = text.split(s).join('[REDACTED]');
    const encoded = Buffer.from(s).toString('base64');
    if (encoded.length > 4) text = text.split(encoded).join('[REDACTED]');
  }
  return text.replace(/(AUTH\s+(?:PLAIN|LOGIN|CRAM-MD5))\s+\S+/gi, '$1 [REDACTED]');
}
