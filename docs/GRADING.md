# SMTP security and connectivity grading

Available in the beta.3 source candidate. The image is not available until its release is approved and published.

Every completed SMTP probe includes `grading` in its streamed result. The browser displays that assessment and includes it in copied/downloaded reports. Input-validation and DNS errors occur before an SMTP probe and have no scorecard. A browser request/stream failure clears old grades and shows the request failure.

## Policy v1

These are SMTP Probe's own connection assessment rules, not an external certification or a server-wide score. No extra probes, authentication attempts or emails are generated for grading.

| Grade | Observed connection |
| --- | --- |
| A | Validated TLS 1.3 with a recognized modern cipher and no observed expiry warning. |
| B | Validated TLS 1.2 with ECDHE and AEAD, or otherwise A-grade TLS with a certificate expiring within 30 days. |
| C | Validated TLS 1.2/1.3 with an unrecognized cipher or one outside this policy's modern cipher set; review the negotiated cipher. |
| F | Plaintext selected and TCP connected, required STARTTLS absent, TLS handshake/validation failure, obsolete/unrecognized TLS protocol, or an observed expired certificate. |
| N/A | Connection ended before transport security could be assessed, such as TCP failure. |

Modern ciphers here are the TLS 1.3 AES-GCM/ChaCha20 suites, and TLS 1.2 ECDHE-RSA/ECDHE-ECDSA AES-GCM or ChaCha20-Poly1305. TLS 1.2 remains supported; its B grade is a product distinction from TLS 1.3, not a claim that TLS 1.2 is inherently broken. Missing certificate expiry is marked unknown. TLS validation uses Node.js and the host/container trust configuration; certificate failures remain fail-closed.

Connectivity shows the result of the requested operation independently of the security grade. It records TCP, 220 banner, successful EHLO, completed TLS, successful authentication and accepted submission as they actually occur. Unattempted stages remain **NOT TESTED**. For STARTTLS, capabilities are cleared and queried again after encryption. If that EHLO fails, pre-TLS capabilities are not presented as post-TLS findings. A successful verify without credentials does not claim authentication or delivery succeeded. Accepted submission does not confirm inbox delivery.

Authentication mechanisms and EHLO capabilities are informational. No advertised AUTH is normal for many relay/MX servers and does not reduce the transport grade. PLAIN/LOGIN over validated TLS do not lower the grade. Advertising AUTH before TLS creates a review warning but does not prove that a server accepts plaintext credentials. SMTP Probe never sends credentials before TLS. No capability earns security points.

The security grade applies only to the selected hostname, address, port, mode and negotiated session. It does not enumerate all supported protocols/ciphers or test open relay, SPF, DKIM, DMARC, MTA-STS, DANE, revocation checking, certificate transparency, server enforcement on other connections, or inbox delivery. It is intended to help diagnose SMTP connections, not replace a security audit.

References: [RFC 8314](https://www.rfc-editor.org/rfc/rfc8314.html), [RFC 8997](https://www.rfc-editor.org/rfc/rfc8997.html) and [RFC 3207](https://www.rfc-editor.org/rfc/rfc3207.html). Numeric grade thresholds are this project's policy.

## Beta.3 operator acceptance checks

After publication, set `SMTP_PROBE_IMAGE=ghcr.io/texomans/smtp-probe:v0.2.0-beta.3` in Komodo's effective environment, pull and redeploy. Existing Compose defaults remain pinned to beta.1 and are fallback values only; use an explicit environment override for the selected release. Confirm the startup log and UI show beta.3.

1. Verify a known SMTP server with STARTTLS and no credentials: TLS grade and capability findings appear; authentication and submission show NOT TESTED.
2. Verify valid credentials over TLS: authentication passes. Try an invalid password: connectivity fails at authentication while validated TLS retains its security grade.
3. Use No TLS on an endpoint permitting EHLO: connectivity can pass while security is F. No credential transmission occurs.
4. On endpoints you control, try missing STARTTLS and a certificate hostname mismatch: F with a clear transport finding and no credential transmission.
5. Copy and download a report: both contain the same grade, connectivity checks, findings and scope without credentials.
6. Start another test: the previous scorecard disappears until the new result. Check narrow/mobile layouts as well as desktop.
7. Optional authorized send: accepted SMTP submission passes that stage; it does not claim inbox delivery.

Automated tests use disposable local SMTP fixtures; operator acceptance is intended on the released beta.3 image. Do not publish the candidate or change an existing deployment until approved.
