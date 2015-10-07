from axolotl.state.sessionstore import SessionStore
from axolotl.state.sessionrecord import SessionRecord


class LiteSessionStore(SessionStore):
    def __init__(self, dbConn, cryptostorage):
        """
        :type dbConn: Connection
        """
        self.dbConn = dbConn
        self.cryptostorage = cryptostorage
        dbConn.execute("CREATE TABLE IF NOT EXISTS sessions ("
                       "_id INTEGER PRIMARY KEY AUTOINCREMENT,"
                       "recipient_id TEXT UNIQUE, device_id INTEGER,"
                       "record BLOB, timestamp INTEGER);")

    def loadSession(self, recipientId, deviceId):
        q = "SELECT record FROM sessions WHERE recipient_id = ? AND device_id = ?"
        c = self.dbConn.cursor()
        c.execute(q, (recipientId, deviceId))
        result = c.fetchone()

        if result:
            return SessionRecord(serialized=self.cryptostorage.decrypt(result[0]))
        else:
            return SessionRecord()

    def getSubDeviceSessions(self, recipientId):
        q = "SELECT device_id FROM sessions WHERE recipient_id = ?"
        c = self.dbConn.cursor()
        c.execute(q, (recipientId,))
        result = c.fetchall()

        deviceIds = [r[0] for r in result]
        return deviceIds

    def storeSession(self, recipientId, deviceId, sessionRecord):
        self.deleteSession(recipientId, deviceId)

        q = "INSERT INTO sessions(recipient_id, device_id, record) VALUES(?,?,?)"
        c = self.dbConn.cursor()
        c.execute(q, (recipientId, deviceId, self.cryptostorage.encrypt(sessionRecord.serialize())))
        self.dbConn.commit()

    def containsSession(self, recipientId, deviceId):
        q = "SELECT record FROM sessions WHERE recipient_id = ? AND device_id = ?"
        c = self.dbConn.cursor()
        c.execute(q, (recipientId, deviceId))
        result = c.fetchone()

        return result is not None

    def deleteSession(self, recipientId, deviceId):
        q = "DELETE FROM sessions WHERE recipient_id = ? AND device_id = ?"
        self.dbConn.cursor().execute(q, (recipientId, deviceId))
        self.dbConn.commit()

    def deleteAllSessions(self, recipientId):
        q = "DELETE FROM sessions WHERE recipient_id = ?"
        self.dbConn.cursor().execute(q, (recipientId,))
        self.dbConn.commit()

    def getAllSessions(self):
        q = "SELECT recipient_id, device_id, record FROM sessions"
        c = self.dbConn.cursor()
        c.execute(q)
        result = [(r[0], r[1], SessionRecord(serialized=self.cryptostorage.decrypt(r[2])))
                  for r in c.fetchall()]
        return result

    def hasPendingKeyExchange(self, recipientId, deviceId):
        return self.loadSession(recipientId, deviceId).getSessionState().hasPendingKeyExchange()
