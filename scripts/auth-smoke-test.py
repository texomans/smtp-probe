#!/usr/bin/env python3
"""Locally check SMTP Probe's password login and authenticated status on VPS.

The access password is read from a hidden prompt. Never include credentials
in a command line, screenshot, ticket, or chat message.
"""
import getpass
import json
import sys
import urllib.error
import urllib.request

BASE = 'http://127.0.0.1:3088'


def call(path, method='GET', payload=None, cookie=None, csrf=None):
    headers = {}
    if payload is not None:
        headers['Content-Type'] = 'application/json'
    if cookie:
        headers['Cookie'] = cookie
    if csrf:
        headers['X-CSRF-Token'] = csrf
    request = urllib.request.Request(
        BASE + path,
        data=json.dumps(payload).encode() if payload is not None else None,
        method=method,
        headers=headers,
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        data = json.load(response)
        return data, response.headers.get('Set-Cookie', '')


def main():
    try:
        health, _ = call('/healthz')
        if health.get('status') != 'ok':
            print('Health check returned an unexpected status.')
            return 1
        pwd = getpass.getpass('SMTP Probe access password (hidden): ')
        login, header = call('/api/login', 'POST', {'password': pwd})
        del pwd
        cookie = header.split(';', 1)[0]
        csrf = login['csrfToken']
        info, _ = call('/api/info', cookie=cookie)
        print('Authentication: PASS')
        print('Version:', info['version'])
        print('Sending enabled:', info['sendEnabled'])
        _, _ = call('/api/logout', 'POST', cookie=cookie, csrf=csrf)
        print('Logout: PASS')
        return 0
    except urllib.error.HTTPError as error:
        try:
            detail = json.load(error).get('error', 'Request was rejected.')
        except (ValueError, OSError):
            detail = 'Request was rejected.'
        print(f'Authentication check failed (HTTP {error.code}): {detail}')
        return 1
    except (KeyError, OSError, ValueError) as error:
        print(f'Authentication check failed: {error}')
        return 1


if __name__ == '__main__':
    sys.exit(main())
