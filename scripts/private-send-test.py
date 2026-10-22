#!/usr/bin/env python3
"""Authenticated private SMTP Probe send test on the same Docker host.

Prompts for both access and SMTP passwords without echoing either.
Runs through the localhost-only service and its CSRF-protected API.
"""
import getpass
import json
import sys
import urllib.error
import urllib.request

API = 'http://127.0.0.1:3088'


def get_json(path, cookie=None):
    headers = {'Cookie': cookie} if cookie else {}
    request = urllib.request.Request(API + path, headers=headers)
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.load(response)


def main():
    try:
        health = get_json('/healthz')
        if health.get('status') != 'ok':
            print('Health check did not pass.')
            return 1
    except (OSError, ValueError) as error:
        print(f'Cannot contact SMTP Probe on the VPS loopback port: {error}')
        return 1

    print('SMTP Probe - authenticated private single-recipient send test')
    access_password = getpass.getpass('SMTP Probe access password (hidden): ')
    login_request = urllib.request.Request(
        API + '/api/login',
        method='POST',
        data=json.dumps({'password': access_password}).encode('utf-8'),
        headers={'Content-Type': 'application/json'},
    )
    del access_password
    try:
        with urllib.request.urlopen(login_request, timeout=10) as response:
            auth_data = json.load(response)
            cookie = response.headers.get('Set-Cookie', '').split(';', 1)[0]
        csrf = auth_data['csrfToken']
        info = get_json('/api/info', cookie)
    except urllib.error.HTTPError as error:
        print(f'Application login failed (HTTP {error.code}).')
        return 1
    except (OSError, KeyError, ValueError) as error:
        print(f'Cannot authenticate to SMTP Probe: {error}')
        return 1

    if info.get('sendEnabled') is not True:
        print('Sending is disabled. Enable the private-send Compose override first.')
        return 1

    print('Target: mail.smtp2go.com:587 (mandatory STARTTLS)')
    username = input('SMTP2GO username: ').strip()
    smtp_password = getpass.getpass('SMTP2GO password (hidden): ')
    sender = input('From address (verified sender): ').strip()
    recipient = input('To address (your inbox): ').strip()
    if not all((username, smtp_password, sender, recipient)):
        print('All four fields are required.')
        return 1
    print(f'\nYou are about to submit ONE real email from {sender} to {recipient}.')
    if input('Type SEND to continue: ').strip() != 'SEND':
        print('Cancelled; no message submitted.')
        return 0

    payload = {
        'host': 'mail.smtp2go.com',
        'port': 587,
        'tlsMode': 'starttls',
        'mode': 'send',
        'username': username,
        'password': smtp_password,
        'authMethod': 'auto',
        'from': sender,
        'to': recipient,
        'subject': 'SMTP Probe authenticated delivery test',
        'message': 'This is a single-recipient SMTP Probe private test.\n',
    }
    request = urllib.request.Request(
        API + '/api/test',
        method='POST',
        data=json.dumps(payload).encode('utf-8'),
        headers={'Content-Type':'application/json','Cookie':cookie,'X-CSRF-Token':csrf},
    )
    del payload, smtp_password
    result = None
    try:
        with urllib.request.urlopen(request, timeout=55) as response:
            for raw in response:
                if not raw.startswith(b'data: '):
                    continue
                event = json.loads(raw[6:])
                if event.get('type') == 'transcript':
                    print(event.get('text', ''), flush=True)
                elif event.get('type') == 'result':
                    result = event
    except urllib.error.HTTPError as error:
        try:
            detail = json.load(error).get('error', 'Request rejected.')
        except ValueError:
            detail = 'Request rejected.'
        print(f'Request failed (HTTP {error.code}): {detail}')
        return 1
    except (OSError, ValueError) as error:
        print(f'Request failed: {error}')
        return 1
    finally:
        try:
            logout = urllib.request.Request(API + '/api/logout', method='POST',
                headers={'Cookie':cookie,'X-CSRF-Token':csrf})
            urllib.request.urlopen(logout, timeout=10).close()
        except OSError:
            pass

    if result is None:
        print('No final result from SMTP Probe.')
        return 1
    print('\nRESULT:', 'PASS' if result.get('ok') else 'FAIL')
    print('Message:', result.get('message'))
    print('Elapsed:', result.get('durationMs'), 'ms')
    if result.get('ok') and result.get('delivery'):
        delivery = result['delivery']
        print('SMTP acceptance:', delivery.get('smtpCode'), delivery.get('smtpResponse'))
        print('Message ID:', result.get('messageId'))
        print('Recipient:', delivery.get('recipient'))
        print('Reminder: SMTP acceptance is not proof of inbox delivery.')
    return 0 if result.get('ok') else 1


if __name__ == '__main__':
    sys.exit(main())
