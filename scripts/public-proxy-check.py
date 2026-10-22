#!/usr/bin/env python3
"""Read-only HTTPS reverse-proxy checks; never asks for secrets or sends email."""
import json
import sys
import urllib.error
import urllib.request

ORIGIN = sys.argv[1] if len(sys.argv) > 1 else sys.exit('Usage: public-proxy-check.py https://smtp.example.com')
if not ORIGIN.startswith('https://') or ORIGIN.endswith('/'):
    sys.exit('Pass a full HTTPS origin without a trailing slash.')
failures = 0

def check(label, path, expected, post=False):
    global failures
    headers = {'Content-Type': 'application/json'} if post else {}
    request = urllib.request.Request(
        ORIGIN + path, headers=headers,
        data=b'{}' if post else None,
        method='POST' if post else 'GET',
    )
    try:
        result = urllib.request.urlopen(request, timeout=15)
    except urllib.error.HTTPError as exc:
        result = exc
    except (OSError, ValueError) as exc:
        print(f'FAIL {label}: {exc.__class__.__name__}')
        failures += 1
        return None
    with result:
        code = result.status
        data = result.read(10_000)
        response_headers = result.headers
    ok = code == expected
    print(f"{'PASS' if ok else 'FAIL'} {label}: HTTP {code} (expected {expected})")
    if not ok:
        failures += 1
    return response_headers, data

page = check('HTTPS page', '/', 200)
check('Health', '/healthz', 200)
check('Anonymous API info denied', '/api/info', 401)
check('Anonymous SMTP API denied', '/api/test', 401, post=True)
session = check('Session status', '/api/session', 200)
if session:
    try:
        authenticated = json.loads(session[1]).get('authenticated')
        ok = authenticated is False
    except (ValueError, TypeError):
        ok = False
    print(f"{'PASS' if ok else 'FAIL'} No anonymous session")
    if not ok:
        failures += 1
if page:
    for name, header, value in [
        ('No-store', 'cache-control', 'no-store'),
        ('Clickjacking protection', 'x-frame-options', 'deny'),
        ('CSP', 'content-security-policy', "default-src 'none'"),
        ('HSTS', 'strict-transport-security', 'max-age='),
    ]:
        ok = value in page[0].get(header, '').lower()
        print(f"{'PASS' if ok else 'FAIL'} {name}")
        if not ok:
            failures += 1
print(f"\n{'PASS' if not failures else 'FAIL'}: {failures} gateway check(s) failed.")
sys.exit(1 if failures else 0)
