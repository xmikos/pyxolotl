import sys, email, email.header, email.utils, email.mime.text

from pyxolotl.encoder.base64 import Encoder
from pyxolotl.protocol.basic import Message


def decode_header(header):
    """Decode email header"""
    parts = [
        s.decode(charset or 'utf-8') if hasattr(s, 'decode') else s
        for s, charset in email.header.decode_header(header)
    ]
    return ' '.join(parts)


def parse_email(message):
    """Parse email message"""
    msg = email.message_from_string(message)
    parts = []
    for part in msg.walk():
        if part.get_content_type() == 'text/plain':
            parts.append(part.get_payload(decode=True).decode(
                part.get_content_charset() or 'utf-8'
            ))

    from_addr = email.utils.parseaddr(decode_header(msg['From']))
    to_addr = email.utils.getaddresses([decode_header(h) for h in msg.get_all('To')])
    subject = decode_header(msg['Subject'])
    return {'from': from_addr, 'to': to_addr, 'subject': subject, 'body': parts}


def create_email(from_addr, to_addr, subject, body, charset='utf-8'):
    """Create email message"""
    msg = email.mime.text.MIMEText(body, 'plain', charset)
    msg['Subject'] = email.header.Header(subject, charset)
    msg['From'] = email.header.Header(from_addr, charset)
    msg['To'] = email.header.Header(to_addr, charset)
    return msg


class Transport:
    """Email message transport"""
    def __init__(self, address, subject='', encoder=None):
        self.encoder = encoder or Encoder()
        self.address = address
        self.subject = subject

    def send(self, message):
        """Send email message (write it to stdout)"""
        if message:
            body = self.encoder.encode(message.serialize()).decode('ascii')
            email_message = create_email(self.address, message.identity, self.subject, body)
            sys.stdout.write(email_message.as_string())

    def receive(self, message=''):
        """Receive email message (read it from stdin)"""
        if not message:
            message = sys.stdin.read()

        email_message = parse_email(message)
        sender = email_message['from'][1]
        body = email_message['body'][0]
        if sender and body:
            return Message.from_raw(sender, self.encoder.decode(body.encode('ascii')))
