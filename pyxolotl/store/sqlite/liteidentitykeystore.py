from axolotl.state.identitykeystore import IdentityKeyStore
from axolotl.identitykey import IdentityKey
from axolotl.identitykeypair import IdentityKeyPair
from axolotl.ecc.djbec import DjbECPrivateKey, DjbECPublicKey


class LiteIdentityKeyStore(IdentityKeyStore):
    def __init__(self, dbConn, cryptostorage):
        """
        :type dbConn: Connection
        """
        self.dbConn = dbConn
        self.cryptostorage = cryptostorage
        dbConn.execute("CREATE TABLE IF NOT EXISTS identities ("
                       "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                       "recipient_id TEXT UNIQUE,"
                       "registration_id INTEGER, public_key BLOB, private_key BLOB,"
                       "next_prekey_id INTEGER, timestamp INTEGER);")

    def getIdentityKeyPair(self):
        q = "SELECT public_key, private_key FROM identities WHERE recipient_id = -1"
        c = self.dbConn.cursor()
        c.execute(q)
        result = c.fetchone()

        publicKey, privateKey = result
        privateKey = self.cryptostorage.decrypt(privateKey)
        return IdentityKeyPair(IdentityKey(DjbECPublicKey(publicKey[1:])),
                               DjbECPrivateKey(privateKey))

    def getLocalRegistrationId(self):
        q = "SELECT registration_id FROM identities WHERE recipient_id = -1"
        c = self.dbConn.cursor()
        c.execute(q)
        result = c.fetchone()
        return result[0] if result else None

    def storeLocalData(self, registrationId, identityKeyPair):
        q = ("INSERT INTO identities(recipient_id, registration_id, public_key, private_key) "
             "VALUES(-1, ?, ?, ?)")
        c = self.dbConn.cursor()
        c.execute(q, (registrationId, identityKeyPair.getPublicKey().getPublicKey().serialize(),
                      self.cryptostorage.encrypt(identityKeyPair.getPrivateKey().serialize())))

        self.dbConn.commit()

    def saveIdentity(self, recipientId, identityKey):
        q = "DELETE FROM identities WHERE recipient_id=?"
        self.dbConn.cursor().execute(q, (recipientId,))
        self.dbConn.commit()

        q = "INSERT INTO identities (recipient_id, public_key) VALUES(?, ?)"
        c = self.dbConn.cursor()
        c.execute(q, (recipientId, identityKey.getPublicKey().serialize()))
        self.dbConn.commit()

    def isTrustedIdentity(self, recipientId, identityKey):
        q = "SELECT public_key FROM identities WHERE recipient_id = ?"
        c = self.dbConn.cursor()
        c.execute(q, (recipientId,))
        result = c.fetchone()
        if not result:
            return True
        return result[0] == identityKey.getPublicKey().serialize()

    def getAllIdentities(self):
        q = "SELECT recipient_id, public_key FROM identities WHERE recipient_id != -1"
        c = self.dbConn.cursor()
        c.execute(q)
        result = c.fetchall()
        return result
