from axolotl.state.signedprekeystore import SignedPreKeyStore
from axolotl.state.signedprekeyrecord import SignedPreKeyRecord
from axolotl.invalidkeyidexception import InvalidKeyIdException


class LiteSignedPreKeyStore(SignedPreKeyStore):
    def __init__(self, dbConn, cryptostorage):
        """
        :type dbConn: Connection
        """
        self.dbConn = dbConn
        self.cryptostorage = cryptostorage
        dbConn.execute("CREATE TABLE IF NOT EXISTS signed_prekeys ("
                       "_id INTEGER PRIMARY KEY AUTOINCREMENT,"
                       "prekey_id INTEGER UNIQUE, timestamp INTEGER, record BLOB);")

    def loadSignedPreKey(self, signedPreKeyId):
        q = "SELECT record FROM signed_prekeys WHERE prekey_id = ?"

        cursor = self.dbConn.cursor()
        cursor.execute(q, (signedPreKeyId,))

        result = cursor.fetchone()
        if not result:
            raise InvalidKeyIdException("No such signedprekeyrecord! %s " % signedPreKeyId)

        return SignedPreKeyRecord(serialized=self.cryptostorage.decrypt(result[0]))

    def loadSignedPreKeys(self):
        q = "SELECT record FROM signed_prekeys"

        cursor = self.dbConn.cursor()
        cursor.execute(q,)
        result = cursor.fetchall()
        results = []
        for row in result:
            results.append(SignedPreKeyRecord(serialized=self.cryptostorage.decrypt(row[0])))

        return results

    def storeSignedPreKey(self, signedPreKeyId, signedPreKeyRecord):
        #self.removeSignedPreKey(signedPreKeyId)

        q = "INSERT INTO signed_prekeys (prekey_id, record) VALUES(?,?)"
        cursor = self.dbConn.cursor()
        cursor.execute(q, (signedPreKeyId, self.cryptostorage.encrypt(signedPreKeyRecord.serialize())))
        self.dbConn.commit()

    def containsSignedPreKey(self, signedPreKeyId):
        q = "SELECT record FROM signed_prekeys WHERE prekey_id = ?"
        cursor = self.dbConn.cursor()
        cursor.execute(q, (signedPreKeyId,))
        return cursor.fetchone() is not None

    def removeSignedPreKey(self, signedPreKeyId):
        q = "DELETE FROM signed_prekeys WHERE prekey_id = ?"
        cursor = self.dbConn.cursor()
        cursor.execute(q, (signedPreKeyId,))
        self.dbConn.commit()
