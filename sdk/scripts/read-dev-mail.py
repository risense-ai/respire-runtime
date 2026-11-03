#!/usr/bin/env python3
"""Read a requested smoke-test email through TLS IMAP; never log message contents."""

import datetime
import email.policy
from email.parser import BytesParser
import imaplib
import json
import os
import re
import ssl
import sys
import time


def read_code(request):
    host = os.environ['RSRS_DEV_IMAP_HOST']
    username = os.environ['RSRS_DEV_IMAP_USERNAME']
    password = os.environ['RSRS_DEV_IMAP_PASSWORD']
    since = datetime.datetime.fromisoformat(request['requestedAt'].replace('Z', '+00:00'))
    recipient = request['recipient']
    if not re.fullmatch(r'[A-Za-z0-9._+\-]+@[A-Za-z0-9.\-]+', recipient):
        raise ValueError('invalid recipient')
    subjects = {'verify_email': 'Respire email verification', 'reset_password': 'Respire password reset'}
    subject = subjects[request['purpose']]
    with imaplib.IMAP4_SSL(host, 993, ssl_context=ssl.create_default_context(), timeout=15) as mailbox:
        mailbox.login(username, password)
        status, _ = mailbox.select('INBOX', readonly=True)
        if status != 'OK':
            raise RuntimeError('inbox unavailable')
        # Search one extra day for server timezone differences, then filter exact receipt times.
        search_date = since - datetime.timedelta(days=1)
        months = ('Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec')
        date = f'{search_date.day:02d}-{months[search_date.month - 1]}-{search_date.year}'
        status, rows = mailbox.uid('search', None, f'(SINCE "{date}" TO "{recipient}" SUBJECT "{subject}")')
        if status != 'OK':
            raise RuntimeError('mail search failed')
        for uid in reversed(rows[0].split()[-50:]):
            status, data = mailbox.uid('fetch', uid, '(BODY.PEEK[] INTERNALDATE)')
            if status != 'OK':
                raise RuntimeError('mail fetch failed')
            for item in data:
                if not isinstance(item, tuple):
                    continue
                received = imaplib.Internaldate2tuple(item[0])
                if received is None or time.mktime(received) < since.timestamp() - 2:
                    continue
                message = BytesParser(policy=email.policy.default).parsebytes(item[1])
                if str(message.get('Subject', '')) != subject:
                    continue
                parts = message.walk() if message.is_multipart() else [message]
                for part in parts:
                    if part.get_content_type() == 'text/plain':
                        match = re.search(r'verification code is (\d{6})\b', part.get_content())
                        if match:
                            return match.group(1)
    return None


if __name__ == '__main__':
    try:
        result = read_code(json.loads(sys.argv[1]))
    except Exception:
        print('Development mailbox reader failed.', file=sys.stderr)
        sys.exit(1)
    print(json.dumps({'code': result}))
