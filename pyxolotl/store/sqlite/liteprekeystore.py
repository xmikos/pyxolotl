from axolotl.state.prekeystore import PreKeyStore
from axolotl.state.prekeyrecord import PreKeyRecord


class LitePreKeyStore(PreKeyStore):
    def __init__(self, dbConn, cryptostorage):
        """
        :type dbConn: Connection
        """
        self.dbConn = dbConn
        self.cryptostorage = cryptostorage
        dbConn.execute("CREATE TABLE IF NOT EXISTS prekeys ("
                       "_id INTEGER PRIMARY KEY AUTOINCREMENT,"
                       "prekey_id INTEGER UNIQUE, sent_to_server BOOLEAN, record BLOB);")

    def loadPreKey(self, preKeyId):
        q = "SELECT record FROM prekeys WHERE prekey_id = ?"

        cursor = self.dbConn.cursor()
        cursor.execute(q, (preKeyId,))

        result = cursor.fetchone()
        if not result:
            raise Exception("No such prekeyRecord!")

        return PreKeyRecord(serialized=self.cryptostorage.decrypt(result[0]))

    def loadPendingPreKeys(self):
        q = "SELECT record FROM prekeys"
        cursor = self.dbConn.cursor()
        cursor.execute(q)
        result = cursor.fetchall()

        return [PreKeyRecord(serialized=self.cryptostorage.decrypt(result[0])) for result in result]

    def storePreKey(self, preKeyId, preKeyRecord):
        #self.removePreKey(preKeyId)
        q = "INSERT INTO prekeys (prekey_id, record) VALUES(?,?)"
        cursor = self.dbConn.cursor()
        cursor.execute(q, (preKeyId, self.cryptostorage.encrypt(preKeyRecord.serialize())))
        self.dbConn.commit()

    def containsPreKey(self, preKeyId):
        q = "SELECT record FROM prekeys WHERE prekey_id = ?"
        cursor = self.dbConn.cursor()
        cursor.execute(q, (preKeyId,))
        return cursor.fetchone() is not None

    def removePreKey(self, preKeyId):
        q = "DELETE FROM prekeys WHERE prekey_id = ?"
        cursor = self.dbConn.cursor()
        cursor.execute(q, (preKeyId,))
        self.dbConn.commit()
