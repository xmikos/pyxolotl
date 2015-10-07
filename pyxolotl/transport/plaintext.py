from pyxolotl.encoder.base64 import Encoder
from pyxolotl.protocol.basic import Message


class Transport:
    """Plaintext message transport"""
    def __init__(self, encoder=None):
        self.encoder = encoder or Encoder()

    def send(self, message):
        """Send message (print it to terminal)"""
        if message:
            body = self.encoder.encode(message.serialize()).decode('ascii')
            print('SEND:')
            print('To: {}'.format(message.identity))
            print('Encrypted message: {}'.format(body))

    def receive(self, message=''):
        """Receive message (read it from terminal)"""
        if not message:
            print('RECEIVE:')
            sender = input('From: ')
            body = input('Encrypted message: ')
            print()
        else:
            sender, body = message.strip().split(None, maxsplit=1)

        if sender and body:
            return Message.from_raw(sender, self.encoder.decode(body.encode('ascii')))
