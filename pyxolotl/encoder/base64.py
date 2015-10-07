import binascii, base64


class Encoder:
    """Base64 (without padding) encoder/decoder"""
    def __init__(self, padding=False):
        self.padding = padding

    def encode(self, data):
        """Encode bytes"""
        encoded = base64.b64encode(data)
        if not self.padding:
            encoded = encoded.rstrip(b'=')

        return bytes(encoded)

    def decode(self, data):
        """Decode bytes"""
        if not self.padding:
            data = data + b'=' * (-len(data) % 4)

        try:
            decoded = base64.b64decode(data)
        except binascii.Error:
            raise ValueError('Data is not Base64 encoded!')

        return bytes(decoded)
