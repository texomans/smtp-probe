import { Resolver } from 'node:dns/promises';
import { domainToASCII } from 'node:url';
import { isIP } from 'node:net';
import { createPublicKey } from 'node:crypto';
import { InputError } from './safety.mjs';

export const DNS_SCOPE = 'DNS configuration diagnostics only. No email sent. SPF sender-IP authorization, DKIM message signatures and actual DMARC pass/fail are not evaluated. Alignment is conditional on the supplied identities authenticating successfully. DNSSEC and external report-destination authorization are not verified. DMARC discovery uses RFC 9989; legacy receivers can differ.';
const missingCodes = new Set(['ENODATA', 'ENOTFOUND']);
const issue = (level, message) => ({level, message});
const statusFor = findings => findings.some(x => x.level === 'error') ? 'error' : findings.some(x => x.level === 'warning') ? 'warning' : 'ok';

export function normalizeDomain(value, label = 'domain') {
  if (typeof value !== 'string' || value.length > 253 || /[\s/@:?#\\\x00-\x1f]/.test(value)) throw new InputError(`Enter a DNS ${label}, without an email address or URL.`);
  const domain = domainToASCII(value.replace(/\.$/, '').toLowerCase());
  if (!domain || domain.length > 253 || isIP(domain) || !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(domain)
      || /(?:^|\.)(?:localhost|local|internal|onion|invalid|test|example|arpa)$/.test(domain)) throw new InputError(`Use a public DNS ${label}; IP literals and internal names are blocked.`);
  return domain;
}
// SPF domain-specs commonly use service labels such as _spf.provider.com.
function normalizeQueryDomain(value) {
  if (typeof value !== 'string') throw new InputError('Invalid DNS query domain.');
  const domain=domainToASCII(value.replace(/\.$/, '').toLowerCase());
  normalizeDomain(domain.replaceAll('_','a'));
  if (!domain.split('.').every(label=>/^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$/.test(label))) throw new InputError('Invalid DNS query domain.');
  return domain;
}
export function validateDnsInput(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new InputError('Invalid DNS diagnostic request.');
  const fromDomain = normalizeDomain(input.fromDomain, 'From domain');
  const envelopeDomain = input.envelopeDomain ? normalizeDomain(input.envelopeDomain, 'MAIL FROM domain') : null;
  const dkimDomain = input.dkimDomain ? normalizeDomain(input.dkimDomain, 'DKIM signing domain') : null;
  if (typeof (input.selectors ?? '') !== 'string' || (input.selectors ?? '').length > 260) throw new InputError('Enter up to four comma-separated DKIM selectors.');
  const selectors = [...new Set((input.selectors ?? '').split(',').map(x => x.trim()).filter(Boolean))];
  if (selectors.length > 4 || selectors.some(x => x.length > 63 || !/^[a-z0-9](?:[a-z0-9_-]*[a-z0-9])?$/i.test(x))) throw new InputError('Use up to four selectors, each at most 63 letters, numbers, hyphens or underscores.');
  if ([fromDomain,envelopeDomain,dkimDomain].filter(Boolean).some(x=>('_dmarc.'+x).length>253)) throw new InputError('The domain is too long for a DMARC DNS name.');
  if (selectors.some(x => `${x}._domainkey.${dkimDomain || fromDomain}`.length > 253)) throw new InputError('The selector and DKIM domain form a DNS name that is too long.');
  return {fromDomain, envelopeDomain, dkimDomain, selectors};
}

// TXT chunks within one RR are concatenated. Separate RRs stay separate.
function createLookup(resolver, signal, {maxQueries = 64, timeoutMs = 20000} = {}) {
  const cache = new Map();
  const queries = [];
  const deadline = Date.now() + timeoutMs;
  let bytes = 0;
  async function txt(name) {
    if (cache.has(name)) return cache.get(name);
    if (signal?.aborted || Date.now() >= deadline) return {status:'error', code:'DEADLINE', records:[]};
    if (queries.length >= maxQueries) return {status:'error', code:'QUERY_LIMIT', records:[]};
    const task = (async () => {
      const entry = {name, status:'pending'}; queries.push(entry);
      let timer, onAbort;
      try {
        const cancelled = new Promise((_, reject) => {
          timer = setTimeout(() => reject(Object.assign(new Error(), {code:'ETIMEOUT'})), Math.max(1, Math.min(2500, deadline - Date.now())));
          onAbort = () => reject(Object.assign(new Error(), {code:'ECANCELLED'}));
          signal?.addEventListener('abort', onAbort, {once:true});
          if (signal?.aborted) onAbort();
        });
        const answer = await Promise.race([resolver.resolveTxt(name), cancelled]);
        if (!Array.isArray(answer) || answer.length > 64 || answer.some(parts => !Array.isArray(parts) || parts.some(x => typeof x !== 'string'))) throw Object.assign(new Error(), {code:'RESPONSE_LIMIT'});
        const records = answer.map(parts => parts.join(''));
        const size = records.reduce((n, s) => n + Buffer.byteLength(s), 0);
        bytes += size;
        if (size > 65536 || bytes > 262144 || records.some(s => s.length > 16384)) throw Object.assign(new Error(), {code:'RESPONSE_LIMIT'});
        entry.status = records.length ? 'ok' : 'missing';
        return {status:entry.status, records};
      } catch (error) {
        const code = /^[A-Z_0-9]+$/.test(error.code || '') ? error.code : 'DNS_ERROR';
        entry.status = missingCodes.has(code) ? 'missing' : 'error'; entry.code = code;
        return {status:entry.status, code, records:[]};
      } finally {
        clearTimeout(timer);
        signal?.removeEventListener('abort', onAbort);
      }
    })();
    cache.set(name, task);
    return task;
  }
  return {txt, queries};
}

export function parseSpf(record) {
  const findings = [], references = [];
  const terms = record.trim().split(/ +/);
  if (!/^v=spf1$/i.test(terms.shift() || '') || /[\t\r\n\x00-\x1f]/.test(record)) findings.push(issue('error', 'Malformed SPF version or whitespace.'));
  if (terms.length > 200) return {findings:[issue('warning','SPF record exceeds the diagnostic 200-term parsing limit.')],references:[],lookups:0,limited:true};
  let lookups = 0, terminal = false;
  const modifiers = new Set();
  for (const raw of terms) {
    const modifier = /^([a-z][a-z0-9_.-]*)=(.+)$/i.exec(raw);
    if (modifier) {
      const name = modifier[1].toLowerCase(), value = modifier[2];
      if (modifiers.has(name)) findings.push(issue('error', `Duplicate SPF modifier: ${name}.`));
      modifiers.add(name);
      if (name === 'redirect') references.push({kind:'redirect', domain:value});
      else if (name === 'exp') findings.push(issue('info', 'SPF exp explanation is not queried.'));
      continue;
    }
    if (raw.includes('%')) {
      findings.push(issue('warning', `SPF macro term requires message context and is not expanded: ${raw}.`));
      if (!terminal && /^[+?~-]?(include|a|mx|ptr|exists)(?::|\/|$)/i.test(raw)) lookups++;
      continue;
    }
    const match = /^([+?~-]?)([a-z][a-z0-9]*)(?::([^/]+))?(?:\/(\d{1,3}))?(?:\/\/(\d{1,3}))?$/i.exec(raw);
    if (!match) {findings.push(issue('error', `Malformed SPF term: ${raw}.`)); continue;}
    const [, qualifier, rawName, target, v4, v6] = match, name = rawName.toLowerCase();
    const wasTerminal = terminal;
    if (wasTerminal) findings.push(issue('warning', `Unreachable SPF term after all: ${raw}.`));
    if (!['all','include','a','mx','ptr','ip4','ip6','exists'].includes(name)) {findings.push(issue('error', `Unknown SPF mechanism: ${name}.`)); continue;}
    if (['ip4','ip6'].includes(name)) {
      if (!target || isIP(target) !== (name === 'ip4' ? 4 : 6) || v6 !== undefined || (v4 !== undefined && Number(v4) > (name === 'ip4' ? 32 : 128))) findings.push(issue('error', `Invalid address or prefix in ${raw}.`));
    } else if (['a','mx'].includes(name)) {
      if ((v4 !== undefined && Number(v4) > 32) || (v6 !== undefined && Number(v6) > 128)) findings.push(issue('error', `Invalid address prefix in ${raw}.`));
    } else if (v4 !== undefined || v6 !== undefined) findings.push(issue('error', `Unexpected address prefix in ${raw}.`));
    if (['include','exists'].includes(name) && !target) findings.push(issue('error', `${name} requires a domain.`));
    if (name === 'all') {
      if (target) findings.push(issue('error', 'The all mechanism cannot have a domain.'));
      terminal = true;
      if (!wasTerminal && (qualifier === '+' || !qualifier)) findings.push(issue('error', '+all authorizes every sender; remove this permissive policy.'));
      if (!wasTerminal && ['~','?'].includes(qualifier)) findings.push(issue('warning', `${raw} does not produce a hard fail for unmatched senders.`));
    }
    if (!wasTerminal && ['include','a','mx','ptr','exists'].includes(name)) lookups++;
    if (name === 'ptr') findings.push(issue('warning', 'SPF ptr is discouraged and is not expanded by this diagnostic.'));
    if (!wasTerminal && name === 'include' && target) references.push({kind:'include', domain:target});
    if (target && !['ip4','ip6','include'].includes(name)) {
      if (target.includes('%')) findings.push(issue('warning', `SPF macros in ${raw} require message context and are not expanded.`));
      else {try {normalizeQueryDomain(target);} catch {findings.push(issue('error', `Invalid domain in ${raw}.`));}}
    }
  }
  const activeReferences = references.filter(ref => ref.kind !== 'redirect' || !terminal);
  if (terminal && references.some(ref => ref.kind === 'redirect')) findings.push(issue('warning', 'redirect is ignored because this record has an all mechanism.'));
  lookups += activeReferences.filter(x => x.kind === 'redirect').length;
  if (!terminal && !modifiers.has('redirect')) findings.push(issue('warning', 'No all mechanism or redirect; unmatched senders receive neutral.'));
  return {findings, references:activeReferences, lookups};
}
async function inspectSpf(domain, lookup) {
  const nodes = [], findings = [];
  let lookupTerms = 0, visits = 0, incomplete = false;
  async function walk(current, path = []) {
    if (++visits > 24 || path.length > 8) {incomplete = true; findings.push(issue('warning', 'SPF expansion reached the diagnostic depth/visit limit.')); return;}
    if (path.includes(current)) {findings.push(issue('error', `SPF include/redirect cycle: ${[...path,current].join(' → ')}.`)); return;}
    const answer = await lookup.txt(current);
    const records = answer.records.filter(x => /^v=spf1(?: |$)/i.test(x));
    const node = {domain:current, records, findings:[]}; nodes.push(node);
    if (answer.status === 'error') {incomplete = true; node.findings.push(issue('warning', `DNS lookup failed (${answer.code}); SPF is unknown.`));}
    else if (records.length !== 1) node.findings.push(issue('error', records.length ? 'Multiple SPF records; a receiver cannot choose one.' : 'No SPF TXT record found at this domain.'));
    else {
      const parsed = parseSpf(records[0]); node.findings.push(...parsed.findings); lookupTerms += parsed.lookups;
      if (records[0].includes('%') || parsed.limited) incomplete = true;
      for (const reference of parsed.references) {
        if (visits >= 24) {incomplete=true; findings.push(issue('warning','SPF expansion reached the diagnostic visit limit.')); break;}
        if (reference.domain.includes('%')) {incomplete = true; node.findings.push(issue('warning', `Macro in ${reference.kind}; expansion requires message context.`)); continue;}
        try {await walk(normalizeQueryDomain(reference.domain), [...path,current]);}
        catch (error) {if (!(error instanceof InputError)) throw error; node.findings.push(issue('error', `Invalid ${reference.kind} target domain.`));}
      }
    }
  }
  await walk(domain);
  if (lookupTerms > 10) findings.push(issue('warning', `Static expansion contains ${lookupTerms} DNS-causing terms; an evaluated path may exceed SPF's 10-term limit. This is not a sender-IP evaluation.`));
  findings.push(issue('info', 'Static include/redirect inspection only. a/mx/ptr/exists expansion, macro substitution, actual evaluation paths and void-lookup limits require a sender context and are not evaluated.'));
  return {domain, status:statusFor([...findings,...nodes.flatMap(x=>x.findings)]), lookupTerms, incomplete, nodes, findings};
}

function parseTags(record) {
  const tags = Object.create(null), findings = [];
  for (const part of record.split(';')) {
    if (!part.trim()) continue;
    const match = /^\s*([a-z][a-z0-9_]*)\s*=\s*([\x20-\x7e\t]*)$/i.exec(part);
    if (!match) {findings.push(issue('error', 'Malformed tag-value field.')); continue;}
    const name = match[1];
    if (Object.hasOwn(tags, name)) findings.push(issue('error', `Duplicate tag: ${name}.`));
    tags[name] = match[2].trim();
  }
  return {tags, findings};
}
export function parseDmarc(record) {
  const {tags, findings} = parseTags(record);
  if (!/^v\s*=\s*DMARC1\s*(?:;|$)/.test(record)) findings.push(issue('error', 'DMARC must begin with the case-sensitive v=DMARC1 version tag.'));
  let usable = !findings.some(x=>x.level==='error');
  const policies = ['none','quarantine','reject'];
  const uris = value => (value || '').split(',').map(x=>x.trim()).filter(Boolean);
  const validUri = value => {try {const url=new URL(value.replace(/!\d+[kmgt]?$/i,'')); return Boolean(url.protocol && url.pathname) && (url.protocol !== 'mailto:' || /^[^\s@]+@[^\s@]+$/.test(decodeURIComponent(url.pathname)));} catch {return false;}};
  const reports = {rua:uris(tags.rua), ruf:uris(tags.ruf)};
  for (const key of ['rua','ruf']) if (tags[key] !== undefined && (!reports[key].length || reports[key].some(x=>!validUri(x)))) findings.push(issue('warning', `Some ${key} reporting URIs are invalid.`));
  let policy = tags.p || 'none';
  if (!tags.p) findings.push(issue('warning', 'Missing p tag defaults to none under RFC 9989; legacy receivers may reject this record.'));
  if ((tags.p && !policies.includes(tags.p)) || ['sp','np'].some(k => tags[k] !== undefined && !policies.includes(tags[k]))) {
    findings.push(issue('error', 'Invalid p/sp/np policy value.'));
    usable = usable && reports.rua.some(validUri);
    policy = 'none';
    if (usable) findings.push(issue('warning', 'A valid rua URI allows the RFC 9989 p=none fallback for invalid policy tags.'));
  }
  const mode = key => {
    if (tags[key] && !['r','s'].includes(tags[key])) findings.push(issue('warning', `Invalid ${key}; relaxed alignment is the default.`));
    return tags[key] === 's' ? 's' : 'r';
  };
  const aspf = mode('aspf'), adkim = mode('adkim');
  if (tags.psd && !['y','n','u'].includes(tags.psd)) findings.push(issue('warning', 'Invalid psd value; treated as unknown.'));
  if (tags.t && !['y','n'].includes(tags.t)) findings.push(issue('warning', 'Invalid test-mode t value; treated as n.'));
  if (tags.pct !== undefined) findings.push(issue('warning', 'pct is a legacy DMARC tag ignored by RFC 9989; legacy receiver behavior can differ.'));
  if (policy === 'none') findings.push(issue('warning', 'Policy none requests no quarantine or rejection of failing mail.'));
  if (!reports.rua.length) findings.push(issue('warning', 'No aggregate reporting destination (rua) is configured.'));
  if (tags.t === 'y') findings.push(issue('warning', 'DMARC test mode t=y requests reduced policy enforcement.'));
  return {tags:{...tags}, findings, usable, policy, aspf, adkim, psd:['y','n'].includes(tags.psd)?tags.psd:'u', testMode:tags.t==='y', reports};
}

function treeNames(domain) {
  const names=[domain]; let labels=domain.split('.');
  while (labels.length > 1) {labels = labels.length >= 8 ? labels.slice(-7) : labels.slice(1); names.push(labels.join('.'));}
  return names;
}
async function dmarcWalk(domain, lookup) {
  const entries=[];
  for (const name of treeNames(domain)) {
    const answer=await lookup.txt(`_dmarc.${name}`);
    const records=answer.records.filter(x=>/^v\s*=\s*DMARC1\s*(?:;|$)/.test(x));
    const findings=[];
    if (answer.status==='error') {entries.push({domain:name, records, findings:[issue('warning', `DNS lookup failed (${answer.code}); tree discovery is incomplete.`)], error:true}); return {entries, org:null, incomplete:true};}
    if (records.length>1) findings.push(issue('error', 'Multiple DMARC records at this name are discarded for policy discovery.'));
    const parsed=records.length===1 ? parseDmarc(records[0]) : null;
    if (!records.length && answer.records.some(x=>/dmarc/i.test(x))) findings.push(issue('warning', 'No recognized v=DMARC1 record; check version case and tag order.'));
    const entry={domain:name, records, findings, parsed}; entries.push(entry);
    if (parsed?.usable && ['n','y'].includes(parsed.psd)) break;
  }
  const valid=entries.filter(x=>x.parsed?.usable);
  let org;
  for (const entry of valid) {
    if (entry.parsed.psd==='n') {org=entry.domain; break;}
    if (entry.parsed.psd==='y' && entry.domain!==domain) {org=domain.split('.').slice(-(entry.domain.split('.').length+1)).join('.'); break;}
  }
  org ||= valid.at(-1)?.domain || domain;
  return {entries, org, incomplete:false};
}
async function inspectDmarc(domain, lookup) {
  const walk=await dmarcWalk(domain, lookup);
  const direct=walk.entries[0];
  const selected=direct?.parsed?.usable ? direct : walk.org ? walk.entries.find(x=>x.domain===walk.org && x.parsed?.usable) || walk.entries.find(x=>x.parsed?.usable && x.parsed.psd==='y') : null;
  const findings=walk.entries.flatMap(x=>[...x.findings,...(x.parsed?.findings || [])]);
  if (!selected) findings.push(issue(walk.incomplete ? 'warning' : 'error', walk.incomplete ? 'DMARC policy could not be determined because DNS discovery is incomplete.' : 'No applicable DMARC policy record was found.'));
  if (selected && selected.domain!==domain) findings.push(issue('info', `Inherited DMARC policy from ${selected.domain}. Existing and nonexistent subdomain policies are shown separately; domain existence is not inferred.`));
  const parsed=selected?.parsed;
  const policyFallback=parsed?.findings.some(x=>x.level==='error');
  return {domain, status:statusFor(findings), policyDomain:selected?.domain || null, organizationalDomain:walk.org, discovery:walk.entries.map(x=>({domain:x.domain,records:x.records,findings:[...x.findings,...(x.parsed?.findings || [])]})),
    policy:parsed ? {direct:parsed.policy, existingSubdomain:policyFallback ? 'none' : parsed.tags.sp || parsed.policy, nonexistentSubdomain:policyFallback ? 'none' : parsed.tags.np || parsed.tags.sp || parsed.policy, testMode:parsed.testMode, aspf:parsed.aspf, adkim:parsed.adkim, reports:parsed.reports} : null,
    findings, incomplete:walk.incomplete};
}

export function parseDkim(record) {
  const {tags, findings}=parseTags(record);
  if (tags.v !== undefined && (!/^[ \t]*v[ \t]*=[ \t]*DKIM1[ \t]*(?:;|$)/.test(record) || tags.v !== 'DKIM1')) findings.push(issue('error', 'If present, v=DKIM1 must be the first tag with that exact value.'));
  if (!Object.hasOwn(tags,'p')) findings.push(issue('error', 'Missing required public key p tag.'));
  else if (!tags.p) findings.push(issue('error', 'The DKIM key is revoked (empty p tag).'));
  const keyType=tags.k || 'rsa'; let bits=null;
  if (!['rsa','ed25519'].includes(keyType)) findings.push(issue('error', `Unsupported DKIM key type: ${keyType}.`));
  if (tags.p) {
    const value=tags.p.replace(/[ \t]/g,'');
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value) || value.length%4===1) findings.push(issue('error', 'Public key p is not valid base64.'));
    else {
      try {
        const der=Buffer.from(value,'base64');
        if (der.toString('base64').replace(/=+$/,'') !== value.replace(/=+$/,'')) throw new Error();
        if (keyType==='rsa') {
          const key=createPublicKey({key:der,format:'der',type:'spki'});
          if (key.asymmetricKeyType!=='rsa') throw new Error();
          bits=key.asymmetricKeyDetails.modulusLength;
          if (bits<1024) findings.push(issue('error', `RSA key is only ${bits} bits; below the DKIM minimum.`));
          else if (bits<2048) findings.push(issue('warning', `RSA key is ${bits} bits; prefer 2048 bits or stronger.`));
        } else if (keyType==='ed25519') {
          if (der.length!==32) throw new Error();
          createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),der]),format:'der',type:'spki'});
          bits=256;
        }
      } catch {findings.push(issue('error', 'Public key data cannot be parsed for the declared key type.'));}
    }
  }
  if (tags.h && !tags.h.split(':').map(x=>x.trim()).includes('sha256')) findings.push(issue('error', 'Key hash restrictions do not permit SHA-256.'));
  if (tags.s && !tags.s.split(':').map(x=>x.trim()).some(x=>['*','email'].includes(x))) findings.push(issue('error', 'Key service restrictions do not permit email.'));
  if ((tags.t || '').split(':').map(x=>x.trim()).includes('y')) findings.push(issue('warning', 'DKIM key is in testing mode (t=y).'));
  if (tags.h?.split(':').map(x=>x.trim()).includes('sha1')) findings.push(issue('warning', 'Key advertises deprecated SHA-1; use SHA-256.'));
  return {status:statusFor(findings), keyType, bits, findings};
}
async function inspectDkim(domain, selectors, lookup) {
  if (!selectors.length) return {domain,status:'not-tested',selectors:[],findings:[issue('info','No selectors supplied. DKIM selectors cannot be reliably discovered from DNS; copy s= and d= from a DKIM-Signature header.')]};
  const results=[];
  for (const selector of selectors) {
    const name=`${selector}._domainkey.${domain}`, answer=await lookup.txt(name);
    const records=answer.records.filter(x=>/^\s*v\s*=\s*DKIM1(?:\s*;|$)/.test(x) || /(?:^|;)\s*p\s*=/.test(x));
    const findings=[]; let parsed=null;
    if (answer.status==='error') findings.push(issue('warning', `DNS lookup failed (${answer.code}); key status unknown.`));
    else if (records.length!==1) findings.push(issue('error', records.length ? 'Multiple DKIM key records at this selector.' : 'No DKIM public key found for this selector. A different selector may be in use.'));
    else {parsed=parseDkim(records[0]); findings.push(...parsed.findings);}
    results.push({selector,name,records,keyType:parsed?.keyType || null,bits:parsed?.bits || null,status:statusFor(findings),findings});
  }
  return {domain,status:statusFor(results.flatMap(x=>x.findings)),selectors:results,findings:[issue('info','Published keys do not prove outbound mail is signed or that a message signature verifies. TXT queries follow CNAME delegation through the system resolver.')]};
}
async function potentialAlignment(kind, identity, config, dmarc, lookup) {
  const mode=dmarc.policy?.[kind==='SPF' ? 'aspf':'adkim'] || null;
  if (!identity) return {kind,status:'not-tested',mode,detail:'No identity supplied for this comparison.'};
  if (!dmarc.policy) return {kind,identity,status:'unknown',mode,detail:'No applicable DMARC policy could be established.'};
  if (identity===config.fromDomain) return {kind,identity,status:'aligned',mode,detail:'Exact domain match; conditional on successful authentication.'};
  if (mode==='s') return {kind,identity,status:'not-aligned',mode,detail:'Strict alignment requires an exact From-domain match.'};
  const other=await dmarcWalk(identity,lookup);
  if (!dmarc.organizationalDomain || other.incomplete) return {kind,identity,status:'unknown',mode,detail:'DNS errors or diagnostic limits prevented organizational-domain comparison.'};
  const aligned=other.org===dmarc.organizationalDomain;
  return {kind,identity,status:aligned?'aligned':'not-aligned',mode,detail:`RFC 9989 organizational domains: ${dmarc.organizationalDomain} / ${other.org}. Authentication itself is not tested.`};
}
export async function runDnsDiagnostics(input, {resolver, signal, limits} = {}) {
  const config=validateDnsInput(input);
  const owned=!resolver;
  resolver ||= new Resolver({timeout:2000,tries:1});
  const controller=new AbortController();
  const abort=()=>{controller.abort(); if(owned) resolver.cancel();};
  signal?.addEventListener('abort',abort,{once:true});
  if (signal?.aborted) abort();
  const timer=setTimeout(abort,limits?.timeoutMs ?? 20000);
  const lookup=createLookup(resolver,controller.signal,limits);
  try {
    const spf=await inspectSpf(config.envelopeDomain || config.fromDomain,lookup);
    const dmarc=await inspectDmarc(config.fromDomain,lookup);
    const dkim=await inspectDkim(config.dkimDomain || config.fromDomain,config.selectors,lookup);
    const alignment=[];
    alignment.push(await potentialAlignment('SPF',config.envelopeDomain,config,dmarc,lookup));
    alignment.push(await potentialAlignment('DKIM',config.dkimDomain || (config.selectors.length ? config.fromDomain : null),config,dmarc,lookup));
    return {schemaVersion:1,checkedAt:new Date().toISOString(),input:config,scope:DNS_SCOPE,spf,dkim,dmarc,alignment,queries:lookup.queries};
  } finally {clearTimeout(timer);signal?.removeEventListener('abort',abort); if(owned) resolver.cancel();}
}
