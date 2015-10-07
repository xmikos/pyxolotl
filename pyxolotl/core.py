import logging

from axolotl.util.keyhelper import KeyHelper
from axolotl.sessionbuilder import SessionBuilder
from axolotl.sessioncipher import SessionCipher
from axolotl.protocol.prekeywhispermessage import PreKeyWhisperMessage
from axolotl.protocol.whispermessage import WhisperMessage
from axolotl.protocol.keyexchangemessage import KeyExchangeMessage

from pyxolotl.store.sqlite.liteaxolotlstore import LiteAxolotlStore
from pyxolotl.protocol.basic import Message, MessageType
from pyxolotl.exceptions import NoSessionException, PendingKeyExchangeException

logger = logging.getLogger(__name__)


class Pyxolotl:
    """Universal Axolotl encryption"""

    # PreKeys are not used with serverless P2P communication
    COUNT_PREKEYS = 10
    DEFAULT_DEVICE_ID = 1

    def __init__(self, db, cryptostorage):
        self.store = LiteAxolotlStore(db, cryptostorage)
        if not self.store.getLocalRegistrationId():
            self.init_store()

    def init_store(self):
        """Create new identity key pair and initialize database"""
        logger.info('Creating new identity...')
        identityKeyPair = KeyHelper.generateIdentityKeyPair()
        registrationId = KeyHelper.generateRegistrationId()
        preKeys = KeyHelper.generatePreKeys(KeyHelper.getRandomSequence(), self.COUNT_PREKEYS)
        signedPreKey = KeyHelper.generateSignedPreKey(identityKeyPair,
                                                      KeyHelper.getRandomSequence(65536))

        self.store.storeLocalData(registrationId, identityKeyPair)
        self.store.storeSignedPreKey(signedPreKey.getId(), signedPreKey)

        for preKey in preKeys:
            self.store.storePreKey(preKey.getId(), preKey)

    def init_key_exchange(self, recipient):
        """Send initial key exchange message to recipient"""
        logger.info('Sending initial key exchange message to {}...'.format(recipient))
        sessionBuilder = self.getSessionBuilder(recipient)
        keyExchangeMessage = sessionBuilder.processInitKeyExchangeMessage()
        return Message(recipient, keyExchangeMessage.serialize(), MessageType.KEY)

    def send(self, recipient, plaintext):
        """Send encrypted message to recipient"""
        if self.store.containsSession(recipient, self.DEFAULT_DEVICE_ID):
            if not self.store.sessionStore.hasPendingKeyExchange(recipient, self.DEFAULT_DEVICE_ID):
                logger.info('Sending encrypted message to {}...'.format(recipient))
                sessionCipher = self.getSessionCipher(recipient)
                whisperMessage = sessionCipher.encrypt(plaintext)
                return Message(recipient, whisperMessage.serialize(), MessageType.SECURE)
            else:
                raise PendingKeyExchangeException('Session is in pending key exchange state, '
                                                  'wait for KeyExchangeMessage reply!')
        else:
            raise NoSessionException('Session doesn\'t exists, '
                                     'send initial KeyExchangeMessage first!')

    def end_session(self, recipient):
        """Send end session message to recipient and delete session"""
        if self.store.containsSession(recipient, self.DEFAULT_DEVICE_ID):
            endSessionMessage = None
            if not self.store.sessionStore.hasPendingKeyExchange(recipient, self.DEFAULT_DEVICE_ID):
                logger.info('Sending end session message to {}...'.format(recipient))
                sessionCipher = self.getSessionCipher(recipient)
                endSessionMessage = sessionCipher.encrypt('TERMINATE')

            logger.info('Deleting session for recipient {}...'.format(recipient))
            self.store.deleteSession(recipient, self.DEFAULT_DEVICE_ID)

            if endSessionMessage:
                return Message(recipient, endSessionMessage.serialize(), MessageType.END_SESSION)
        else:
            raise NoSessionException('Session doesn\'t exists!')

    def receive(self, message):
        """Receive encrypted message"""
        if message.message_type == MessageType.KEY:
            decrypted = self.handle_KeyExchangeMessage(message)
        elif message.message_type == MessageType.SECURE:
            decrypted = self.handle_WhisperMessage(message)
        elif message.message_type == MessageType.PREKEY:
            decrypted = self.handle_PreKeyWhisperMessage(message)
        elif message.message_type == MessageType.END_SESSION:
            decrypted = self.handle_EndSessionMessage(message)
        else:
            raise ValueError('Received unknown type of Axolotl message'
                             'from {}!'.format(message.identity))
        return decrypted

    def handle_KeyExchangeMessage(self, message):
        """Handle received key exchange message"""
        #if self.store.containsSession(message.identity, self.DEFAULT_DEVICE_ID):
        #    raise RuntimeError('KeyExchangeMessage received, but session already exists!')

        sessionBuilder = self.getSessionBuilder(message.identity)
        keyExchangeMessage = sessionBuilder.processKeyExchangeMessage(
            KeyExchangeMessage(serialized=message.message)
        )

        if keyExchangeMessage:
            logger.info('Received initial KeyExchangeMessage from {}, '
                        'sending response...'.format(message.identity))
            return Message(message.identity, keyExchangeMessage.serialize(), MessageType.KEY)
        else:
            logger.info('Received response from {} to initial KeyExchangeMessage, '
                        'key exchange completed.'.format(message.identity))

    def handle_PreKeyWhisperMessage(self, message):
        """Handle received PreKey message"""
        logger.info('Received PreKeyWhisperMessage from {}, '
                    'decrypting...'.format(message.identity))
        preKeyWhisperMessage = PreKeyWhisperMessage(serialized=message.message)
        sessionCipher = self.getSessionCipher(message.identity)
        plaintext = sessionCipher.decryptPkmsg(preKeyWhisperMessage)
        return plaintext

    def handle_WhisperMessage(self, message):
        """Handle received encrypted message"""
        logger.info('Received WhisperMessage from {}, decrypting...'.format(message.identity))
        whisperMessage = WhisperMessage(serialized=message.message)
        sessionCipher = self.getSessionCipher(message.identity)
        plaintext = sessionCipher.decryptMsg(whisperMessage)
        return plaintext

    def handle_EndSessionMessage(self, message):
        """Handle end session message"""
        plaintext = self.handle_WhisperMessage(message)
        if plaintext == 'TERMINATE':
            logger.info('Received EndSessionMessage from {}, '
                        'deleting session!'.format(message.identity))
            self.store.deleteSession(message.identity, self.DEFAULT_DEVICE_ID)
        else:
            logger.info('Received EndSessionMessage from {}, but plaintext '
                        'isn\'t "TERMINATE"!'.format(message.identity))
        return plaintext

    def getSessionBuilder(self, identity):
        """Construct SessionBuilder for given identity"""
        return SessionBuilder(self.store, self.store, self.store, self.store,
                              identity, self.DEFAULT_DEVICE_ID)

    def getSessionCipher(self, identity):
        """Construct SessionCipher for given identity"""
        return SessionCipher(self.store, self.store, self.store, self.store,
                             identity, self.DEFAULT_DEVICE_ID)
