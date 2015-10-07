from hashlib import pbkdf2_hmac
from enum import Enum


class MessageType(Enum):
    """Type and prefix of Pyxolotl message"""
    SECURE = b'?TSM'
    KEY = b'?TSK'
    PREKEY = b'?TSP'
    END_SESSION = b'?TSE'


class Message:
    """Basic Pyxolotl message"""

    PREFIX_BYTES = 4
    PREFIX_PBKDF2_ITERATIONS = 100000

    def __init__(self, identity, message, message_type=None):
        self.identity = identity
        self.message = message
        self.message_type = message_type

    @staticmethod
    def detect_message_type(raw_message):
        """Detect type of raw message"""
        for message_type in MessageType:
            if Message.verify_prefix(message_type.value, raw_message):
                return message_type
        raise ValueError('Unknown message type')

    @staticmethod
    def calculate_prefix(prefix, message):
        """Calculate obfuscated message prefix
           (to make traffic analysis/filtering much more resource intensive)"""
        return pbkdf2_hmac('sha256', prefix, message,
                           Message.PREFIX_PBKDF2_ITERATIONS,
                           Message.PREFIX_BYTES)

    @staticmethod
    def verify_prefix(prefix, raw_message):
        """Check if raw message has given prefix"""
        if len(raw_message) <= Message.PREFIX_BYTES:
            return False

        message_prefix = raw_message[:Message.PREFIX_BYTES]
        message_body = raw_message[Message.PREFIX_BYTES:]
        calculated_prefix = Message.calculate_prefix(prefix, message_body)
        return message_prefix == calculated_prefix

    @staticmethod
    def from_raw(sender, raw_message):
        """Create Message object from raw message"""
        message_type = Message.detect_message_type(raw_message)
        message_body = raw_message[Message.PREFIX_BYTES:]
        return Message(sender, message_body, message_type)

    def serialize(self):
        """Serialize Message to bytes"""
        if not isinstance(self.message_type, MessageType):
            raise ValueError('Unknown message type')

        prefix = Message.calculate_prefix(self.message_type.value, self.message)
        return prefix + self.message
