// SMTP Probe policy v1: a grade for this connection, never a server-wide audit.
export const GRADING_SCOPE = 'This connection only. Other TLS versions/ciphers, relay policy, SPF/DKIM/DMARC, MTA-STS/DANE and inbox delivery are not tested. AUTH advertisement does not prove plaintext authentication is accepted.';
export function gradeConnection(config, result, evidence, now = Date.now()) {
  const checks = [];
  const add = (id, label, status, detail) => checks.push({id, label, status, detail});
  const secure = result.tls?.authorized === true;
  let grade = 'N/A';
  let summary = 'Insufficient evidence to grade transport security.';
  if (secure) {
    grade = result.tls.protocol === 'TLSv1.3' ? 'A' : result.tls.protocol === 'TLSv1.2' ? 'B' : 'F';
    summary = grade === 'A' ? 'Modern TLS with a validated certificate.' : grade === 'B' ? 'TLS 1.2 with a validated certificate.' : 'An obsolete or unrecognized TLS protocol was observed.';
    add('transport', 'Encryption', 'pass', 'TLS established; no credentials sent before encryption.');
    add('certificate', 'Certificate validation', 'pass', 'Certificate chain, hostname and validity accepted by Node.js trust validation.');
    add('protocol', 'TLS protocol', grade === 'F' ? 'fail' : 'pass', result.tls.protocol);
    const cipher = result.tls.cipher || 'Unknown';
    const modernCipher = /^(TLS_AES_(128|256)_GCM_SHA(256|384)|TLS_CHACHA20_POLY1305_SHA256)$/.test(cipher) || /^ECDHE-(RSA|ECDSA)-(AES(128|256)-GCM-SHA(256|384)|CHACHA20-POLY1305)$/.test(cipher);
    add('cipher', 'Negotiated cipher', modernCipher ? 'pass' : 'warn', cipher);
    if (!modernCipher && grade !== 'F') {grade = 'C'; summary = 'Validated TLS, but the negotiated cipher needs review.';}
    const expiry = Date.parse(result.tls.certificateChain?.[0]?.expires);
    if (Number.isFinite(expiry)) {
      const days = Math.floor((expiry - now) / 86400000);
      add('expiry', 'Certificate expiry', days < 0 ? 'fail' : days <= 30 ? 'warn' : 'pass', days < 0 ? 'Certificate has expired.' : `${days} day(s) remaining.`);
      if (days < 0) {grade = 'F'; summary = 'The observed certificate has expired.';}
      else if (days <= 30 && grade === 'A') {grade = 'B'; summary = 'Modern validated TLS; renew the certificate soon.';}
    } else add('expiry', 'Certificate expiry', 'unknown', 'Expiry date unavailable.');
  } else if (evidence.tls === 'fail' || evidence.starttls === false) {
    grade = 'F'; summary = 'Required TLS could not be established and validated.';
    add('transport', 'Encryption', 'fail', evidence.starttls === false ? 'STARTTLS was not advertised; encryption was required.' : 'TLS negotiation or certificate validation failed.');
    add('certificate', 'Certificate validation', 'unknown', 'No validated TLS session; see the failure in the transcript.');
  } else if (evidence.tcp === 'pass' && config.tlsMode === 'none') {
    grade = 'F'; summary = 'This test used an unencrypted connection.';
    add('transport', 'Encryption', 'fail', 'No TLS selected. This does not establish whether the server supports TLS.');
    add('certificate', 'Certificate validation', 'unknown', 'Not tested without TLS.');
  } else add('transport', 'Encryption', 'unknown', 'Connection ended before TLS could be assessed.');
  const capabilities = result.capabilities || [];
  const mechanisms = [...new Set(capabilities.flatMap(line => /^AUTH(?:\s|=)/i.test(line.trim()) ? line.trim().replace(/^AUTH[=\s]*/i, '').toUpperCase().split(/\s+/).filter(Boolean) : []))];
  add('auth-methods', 'Advertised authentication', evidence.ehlo === 'pass' ? 'info' : 'unknown', evidence.ehlo === 'pass' ? mechanisms.join(', ') || 'None advertised; this can be normal for relay/MX servers.' : 'EHLO did not complete.');
  if (evidence.plaintextAuth) add('plaintext-auth', 'AUTH before TLS', 'warn', 'Authentication was advertised before TLS. Acceptance without TLS was not tested; SMTP Probe did not send credentials before TLS.');
  add('capabilities', 'SMTP capabilities', evidence.ehlo === 'pass' ? 'info' : 'unknown', evidence.ehlo === 'pass' ? `${capabilities.length} EHLO response line(s) observed. Capabilities are informational and do not earn grade points.` : 'Not available.');
  const connectivity = [
    ['tcp', 'TCP connection'], ['greeting', 'SMTP banner'], ['ehlo', 'EHLO capabilities'],
    ['tls', 'TLS handshake'], ['auth', 'Authentication'], ['submission', 'Message submission'],
  ].map(([id, label]) => ({id, label, status:evidence[id] || 'not-tested'}));
  return {policyVersion:1, grade, summary, scope:GRADING_SCOPE, connectivity:{status:result.ok ? 'pass' : 'fail', checks:connectivity}, checks};
}
