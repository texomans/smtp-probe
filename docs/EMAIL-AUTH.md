# SPF, DKIM and DMARC DNS diagnostics

Beta.4 adds an independent **SPF, DKIM & DMARC** workspace below the SMTP transcript. No SMTP connection, credentials, message upload or email sending is required. DNS reports have their own copy/download buttons and retain the exact input snapshot and timestamp used for the check.

## Inputs

- **From domain:** domain in the visible From address, without a mailbox or URL.
- **MAIL FROM domain:** optional envelope-sender/Return-Path domain. SPF DNS is inspected here when supplied; otherwise SPF is inspected at the From domain and SPF alignment is explicitly not tested. A null MAIL FROM/HELO identity is not inferred.
- **DKIM signing domain:** optional `d=` value from a DKIM-Signature header. If selectors are supplied and this field is blank, the From domain is assumed. This is a conditional identity comparison, not proof that the signer actually uses that domain.
- **Selectors:** up to four comma-separated `s=` values from your provider or a message header. For Microsoft 365 these are often `selector1, selector2`, but use the actual configured selectors. Blank skips key checks; it does not imply missing DKIM. This initial release supports single-label selectors, including hyphens/underscores, up to 63 characters each.

Internationalized domains are normalized to ASCII. IP literals, URLs, mailbox addresses and internal/reserved DNS suffixes are rejected. Diagnostic lookup names can contain service labels such as `_spf`. DNS queries use the container's configured recursive resolvers, including their CNAME handling, caching and split-DNS view. No arbitrary HTTP URLs are fetched and no connection is opened to addresses returned by the queried domains. The query trace shows TXT questions made by SMTP Probe, not the recursive resolver's internal CNAME chain or DNS packets.

## Coverage

**SPF:** concatenate character-string chunks inside each TXT RR, preserve separate RRs, detect absent/multiple records and inspect common mechanism/address/prefix syntax. Expand static include and redirect references, detect cycles, and count DNS-causing terms across inspected branches. Redirect is ignored when `all` is present. Macro-dependent terms are reported as incomplete rather than expanded. A static total over ten is a warning about possible evaluation paths, not an SPF permerror verdict. No sender IP is supplied: mechanism matching, `a`/`mx`/`ptr`/`exists` expansion, macro substitution and the actual ten-term/void-lookup limits of message evaluation are not performed. Unknown modifiers are ignored; this is bounded structural inspection, not a full SPF interpreter.

**DKIM:** inspect explicitly selected TXT key records, including resolver-followed CNAME delegation. Parse RSA SubjectPublicKeyInfo and raw Ed25519 keys, reject malformed base64/key data, flag empty/revoked keys and duplicate key records, report RSA bit length, warn below 2048 bits, reject below 1024 bits, and inspect SHA-256/email restrictions and testing flags. The public key can be published even when outbound mail is unsigned or incorrectly signed. This tool does not verify message signatures, body hashes, canonicalization or header coverage.

**DMARC:** inspect version/tag structure, duplicate records/tags, policy values, reporting URI syntax, strict/relaxed modes and test mode. Use bounded RFC 9989 DNS tree walks and `psd` organizational boundaries for policy discovery and relaxed domain comparisons. Distinguish direct policy from inherited `sp` and conditional `np` policy; domain existence is not inferred. Invalid policy tags with a usable `rua` URI get the current standard's monitoring fallback. Missing `p` defaults to `none` under RFC 9989 and is flagged for legacy compatibility. `pct` is identified as a legacy tag. Published policy and `t=y` test mode are shown separately; receiver action is not predicted. Unknown tags are ignored and malformed/duplicate tag structures are conservatively flagged; the tool is not a full receiving-MTA evaluator.

**Potential alignment:** compare the supplied MAIL FROM and DKIM signing domains with the From domain using the discovered `aspf`/`adkim` mode. Exact matches do not require organizational-domain inference. Relaxed comparisons use independent RFC 9989 tree walks; DNS errors yield unknown. An aligned domain is only a potential DMARC authentication path: that underlying SPF check or DKIM signature must actually pass on a message. No overall DMARC pass/fail is claimed. Older receivers using PSL-based discovery may choose a different organizational domain or policy.

DNSSEC validation, external report-destination authorization, report delivery, mailbox existence and inbox delivery are not verified. Reporting URLs are displayed as text and are never opened. DNS data may change or be cached; the timestamp is when this diagnostic ran, not an authoritative propagation timestamp.

## Limits and failures

The API requires the same login, CSRF and origin checks as SMTP tests. DNS work has separate quotas: six requests per client in five minutes, forty per From domain in fifteen minutes and one hundred per instance per hour. At most three DNS requests run concurrently. Limits are in-memory, per instance.

Each request has a twenty-second deadline, at most sixty-four unique TXT questions, a sixty-four-KiB per-answer and 256-KiB cumulative data budget, at most sixty-four RRs per answer, and a sixteen-KiB per-record ceiling. SPF inspection is capped at twenty-four record visits, eight recursive levels and two hundred terms per record. Each DMARC tree walk uses at most eight target names. Resolver errors/timeouts and diagnostic limits are explicitly unknown/incomplete; they are never treated as proof that a record is absent. Missing records/invalid configurations use error findings; warnings also cover review items such as monitoring-only policies. An OK label means no issue was identified within the inspected coverage, not successful email authentication.

## Test the released beta.4 image

1. Publish the prepared `v0.2.0-beta.4` pre-release targeting `main`, then wait for **Publish GHCR image** to succeed. Set Komodo's effective `SMTP_PROBE_IMAGE` to `ghcr.io/texomans/smtp-probe:v0.2.0-beta.4`, pull and redeploy. Confirm the UI and startup log show beta.4. No local build is needed.
2. Scroll below the SMTP workspace. Check a domain you manage with its real MAIL FROM domain, DKIM `d=` domain and selectors. Compare records with your provider's configuration or `dig TXT` on a host using the same resolver.
3. Leave selectors and MAIL FROM blank. Confirm key checks and SPF alignment are NOT TESTED, rather than failed.
4. Check an unused selector on a domain you manage. It should identify that selector as missing, without claiming the domain never signs mail.
5. Compare a strict DMARC identity mismatch and a relaxed sibling-domain match where you control the records. Alignment remains conditional on authentication.
6. Copy and download the DNS report. Confirm domain identities, raw relevant records, findings, scope and query trace match the displayed result. Start another check and confirm the old report is cleared while it runs.
7. Run an ordinary SMTP verification afterward; its transcript, grading and report should remain independent of DNS results.

Automated coverage uses deterministic resolvers and a real UDP DNS fixture with CNAME-delegated DKIM and split TXT chunks. HTTP/container smoke tests also exercise endpoint authentication, CSRF and invalid input, and return a bounded result with DNS unavailable in the isolated container. Live public-DNS acceptance is performed on the released deployment.

## References

- [SPF — RFC 7208](https://www.rfc-editor.org/rfc/rfc7208.html)
- [DKIM — RFC 6376](https://www.rfc-editor.org/rfc/rfc6376.html)
- [DKIM key strength — RFC 8301](https://www.rfc-editor.org/rfc/rfc8301.html)
- [Ed25519 DKIM — RFC 8463](https://www.rfc-editor.org/rfc/rfc8463.html)
- [Current DMARC — RFC 9989](https://www.rfc-editor.org/rfc/rfc9989.html)
