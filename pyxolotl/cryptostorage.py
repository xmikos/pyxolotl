import os, sys, ctypes, hashlib

from Crypto.Cipher import AES
from Crypto.Hash import SHA256, HMAC


def zero_bytes(s):
    """Zero string of bytes in memory"""
    bufsize = len(s) + 1
    offset = sys.getsizeof(s) - bufsize
    ctypes.memset(id(s) + offset, 0, bufsize)


class DecryptionException(Exception):
    pass


class AlreadyInitializedException(Exception):
    pass


class AlreadyDecryptedException(Exception):
    pass


class NotInitializedException(Exception):
    pass


class NotDecryptedException(Exception):
    pass


class AESCipher:
    """Simple AES-CBC encryption/decryption with PKCS7 padding and HMAC authentication"""
    def __init__(self, key, hmac_key, hash_=SHA256):
        self.key = key
        self.hmac_key = hmac_key
        self.hash_ = hash_

    def pad(self, data, block_size=AES.block_size):
        """PKCS7 padding"""
        pad_len = block_size - len(data) % block_size
        return data + bytes([pad_len]) * pad_len

    def unpad(self, data):
        """PKCS7 unpadding"""
        pad_len = data[-1]
        if data[-pad_len:] == bytes([pad_len]) * pad_len:
            data = data[:-pad_len]
        return data

    def encrypt(self, data, headers=b''):
        """Encrypt then MAC data (you can also specify headers which will be authenticated, but not encrypted)"""
        iv = os.urandom(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        padded_data = self.pad(data)
        encrypted = cipher.encrypt(padded_data)
        hmac = self.hmac(headers + iv + encrypted)
        return headers + iv + encrypted + hmac

    def decrypt(self, data, headers_size=0):
        """Verify then decrypt data (you must specify headers_size if there are headers)"""
        headers = data[:headers_size]
        iv = data[headers_size:(headers_size + AES.block_size)]
        encrypted = data[(headers_size + AES.block_size):-self.hash_.digest_size]
        hmac_orig = data[-self.hash_.digest_size:]

        # Double HMAC Verification:
        # https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2011/february/double-hmac-verification/
        # (maybe not relevant for our use case, but better safe than sorry)
        hmac = self.hmac(headers + iv + encrypted)
        if self.hmac(hmac_orig) != self.hmac(hmac):
            raise DecryptionException('Bad key or corrupted data')

        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted)
        unpadded = self.unpad(decrypted)
        return unpadded

    def hmac(self, data):
        """Generate HMAC of data"""
        return HMAC.new(self.hmac_key, data, digestmod=self.hash_).digest()


class CryptoStorage:
    """Encrypted storage"""
    def __init__(self, mastersecret=b'', rounds=100000, keysize=256, hash_=SHA256):
        self.mastersecret = mastersecret
        self.rounds = rounds
        self.keysize_bytes = int(keysize / 8)
        self.hash_ = hash_
        self.key = b''
        self.hmac_key = b''
        self.is_open = False

    def get_keys_from_passphrase(self, passphrase, salt):
        """Derive key + hmac_key from passphrase and salt"""
        keys = hashlib.pbkdf2_hmac(self.hash_.hashFactory().name, passphrase, salt, self.rounds,
                                   self.keysize_bytes + self.hash_.digest_size)
        return keys

    def encrypt_with_passphrase(self, passphrase, data):
        """Encrypt data with keys derived from passphrase"""
        # Derive key and hmac_key from passphrase and randomly generated salt
        salt = os.urandom(self.hash_.digest_size)
        keys = self.get_keys_from_passphrase(passphrase, salt)
        key, hmac_key = (keys[:self.keysize_bytes], keys[self.keysize_bytes:])

        # Encrypt data with passphrase-derived keys
        cipher = AESCipher(key, hmac_key, self.hash_)
        encrypted_data = cipher.encrypt(data, headers=salt)

        return encrypted_data

    def decrypt_with_passphrase(self, passphrase, data):
        """Decrypt data encrypted with keys derived from passphrase"""
        # Derive key and hmac_key from passphrase and salt stored in data
        salt = data[:self.hash_.digest_size]
        keys = self.get_keys_from_passphrase(passphrase, salt)
        key, hmac_key = (keys[:self.keysize_bytes], keys[self.keysize_bytes:])

        # Decrypt data with passphrase-derived keys
        cipher = AESCipher(key, hmac_key, self.hash_)
        decrypted_data = cipher.decrypt(data, headers_size=self.hash_.digest_size)

        return decrypted_data

    def init_storage(self, passphrase):
        """Create storage with passphrase-encrypted master secret"""
        if not self.is_open and not self.mastersecret:
            # Generate random master secret (key + hmac_key) and encrypt it with passphrase-derived keys
            mastersecret = os.urandom(self.keysize_bytes + self.hash_.digest_size)
            encrypted_mastersecret = self.encrypt_with_passphrase(passphrase, mastersecret)

            # Save encrypted master secret
            self.mastersecret = encrypted_mastersecret
        elif not self.is_open and self.mastersecret:
            raise AlreadyInitializedException('CryptoStorage is already initialized!')
        else:
            raise AlreadyDecryptedException('CryptoStorage is already decrypted!')

    def change_passphrase(self, new_passphrase):
        """Re-encrypt master secret with new passphrase (storage must be opened first)"""
        if self.is_open:
            # Encrypt current mastersecret (key + hmac_key) with keys derived from new passphrase
            mastersecret = self.key + self.hmac_key
            new_encrypted_mastersecret = self.encrypt_with_passphrase(new_passphrase, mastersecret)

            # Save new encrypte mastersecret
            self.mastersecret = new_encrypted_mastersecret
        else:
            raise NotDecryptedException('CryptoStorage is not decrypted!')

    def open_storage(self, passphrase):
        """Decrypt passphrase-encrypted master secret to open storage"""
        if not self.is_open and self.mastersecret:
            # Decrypt master secret (key + hmac_key) with passphrase-derived keys
            encrypted_mastersecret = self.mastersecret
            mastersecret = self.decrypt_with_passphrase(passphrase, encrypted_mastersecret)

            # Save decrypted keys
            self.key = mastersecret[:self.keysize_bytes]
            self.hmac_key = mastersecret[self.keysize_bytes:]

            self.is_open = True
        elif not self.is_open and not self.mastersecret:
            raise NotInitializedException('CryptoStorage is not initialized!')
        else:
            raise AlreadyDecryptedException('CryptoStorage is already decrypted!')

    def close_storage(self):
        """Close storage (delete decrypted master secret)"""
        if self.is_open:
            # Zeroing memory is probably futile here (because Python may have
            # copied key bytes to other addresses in memory)
            zero_bytes(self.key)
            zero_bytes(self.hmac_key)

            self.key = b''
            self.hmac_key = b''

            self.is_open = False
        else:
            raise NotDecryptedException('CryptoStorage is not decrypted!')

    def decrypt(self, encrypted):
        """Decrypt data encrypted with this CryptoStorage"""
        if self.is_open:
            cipher = AESCipher(self.key, self.hmac_key, self.hash_)
            return cipher.decrypt(encrypted)
        else:
            raise NotDecryptedException('CryptoStorage is not decrypted!')

    def encrypt(self, data):
        """Encrypt data with this CryptoStorage"""
        if self.is_open:
            cipher = AESCipher(self.key, self.hmac_key, self.hash_)
            return cipher.encrypt(data)
        else:
            raise NotDecryptedException('CryptoStorage is not decrypted!')


class LiteCryptoStorage(CryptoStorage):
    """Encrypted Storage with mastersecret stored in SQLite database"""
    def __init__(self, db, *args, **kwargs):
        self.db = db
        self.db.execute('CREATE TABLE IF NOT EXISTS mastersecret (k TEXT PRIMARY KEY, v BLOB)')
        super().__init__(*args, **kwargs)

    def get_db_key(self, key):
        q = 'SELECT v FROM mastersecret WHERE k = ?'
        c = self.db.cursor()
        c.execute(q, (key,))
        result = c.fetchone()
        return result[0] if result else b''

    def set_db_key(self, key, value):
        q = 'INSERT OR REPLACE INTO mastersecret (k, v) VALUES (?, ?)'
        c = self.db.cursor()
        c.execute(q, (key, value))
        self.db.commit()

    @property
    def mastersecret(self):
        return self.get_db_key('mastersecret')

    @mastersecret.setter
    def mastersecret(self, value):
        self.set_db_key('mastersecret', value)

    @property
    def default_password(self):
        return self.get_db_key('default_password')

    @default_password.setter
    def default_password(self, value):
        self.set_db_key('default_password', value)
