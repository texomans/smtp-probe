#!/usr/bin/env python3
"""Authenticated HTTPS gateway checks. No SMTP connection or sending is attempted."""
import getpass
import http.cookiejar
import json
import os
import sys
import urllib.error
import urllib.request

origin = sys.argv[1] if len(sys.argv) > 1 else 'https://smtpprobe.texomans.com'
if not origin.startswith('https://') or origin.endswith('/'):
    sys.exit('Provide a valid HTTPS origin without a trailing slash.')
expected_send = os.environ.get('SMTP_PROBE_EXPECT_SEND', '0') == '1'
password = getpass.getpass('SMTP Probe shared access password: ')
if not password:
    sys.exit('No password entered.')

cookies = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookies))
failures = 0

def check(name, correct, detail=''):
    global failures
    print(('PASS' if correct else 'FAIL') + ' ' + name + (': ' + detail if detail else ''))
    if not correct:
        failures += 1

def call(path, data=None, headers=None):
    hdrs = {'Origin': origin} if data is not None else {}
    hdrs.update(headers or {})
    if data is not None:
        hdrs['Content-Type'] = 'application/json'
    request = urllib.request.Request(origin + path, headers=hdrs,
                                     data=json.dumps(data).encode('utf8') if data is not None else None,
                                     method='POST' if data is not None else 'GET')
    try:
        response = opener.open(request, timeout=15)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        content = response.read(16_000)
        try:
            body = json.loads(content)
        except (json.JSONDecodeError, ValueError):
            body = {}
        return response.status, body, response.headers

try:
    code, body, headers = call('/api/login', {'password': password})
    password = None
    check('Login', code == 200 and body.get('ok') is True)
    cookie = headers.get('Set-Cookie', '')
    check('Cookie Secure', '; Secure' in cookie)
    check('Cookie HttpOnly', '; HttpOnly' in cookie)
    check('Cookie SameSite=Strict', '; SameSite=Strict' in cookie)
    check('Cookie __Host- prefix', cookie.startswith('__Host-smtp_probe_sid='))
    check('Cookie host-only', 'Domain=' not in cookie)
    csrf = body.get('csrfToken')
    if code != 200 or not csrf:
        sys.exit('Cannot proceed without an authenticated session; correct the login settings.')
    code, info, _ = call('/api/info')
    check('Authenticated info', code == 200, f'v{info.get("version", "unknown")}')
    check('Sending matches expected deployment setting', info.get('sendEnabled') is expected_send,
          f'sendEnabled={info.get("sendEnabled")}, expected={expected_send}')
    code, _, _ = call('/api/test', {}, {'x-csrf-token': 'bad-token'})
    check('CSRF rejects forged SMTP requests', code == 403, f'HTTP {code}')
    code, _, _ = call('/api/logout', {}, {'x-csrf-token': csrf})
    check('Logout', code == 200, f'HTTP {code}')
    code, _, _ = call('/api/info')
    check('Session revoked', code == 401, f'HTTP {code}')
except (OSError, ValueError) as exc:
    print('FAIL HTTPS connection:', exc.__class__.__name__)
    failures += 1

print(f'\n{"PASS" if failures == 0 else "FAIL"}: {failures} HTTPS authentication check(s) failed.')
sys.exit(1 if failures else 0)
