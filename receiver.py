from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
import json
import base64
from encryption_utils import AsymmetricEncryption, SymmetricEncryption

class Receiver:
    def __init__(self, private_key, sender_public_key):
        self.private_key = RSA.import_key(private_key)
        self.sender_public_key = RSA.import_key(sender_public_key)
        self.asym_enc = AsymmetricEncryption()
        self.sym_enc = SymmetricEncryption()

    def receive_file(self, data):
        data = json.loads(data)
        enc_session_key = base64.b64decode(data['enc_session_key'])
        nonce = base64.b64decode(data['nonce'])
        tag = base64.b64decode(data['tag'])
        ciphertext = base64.b64decode(data['ciphertext'])
        signature = base64.b64decode(data['signature'])

        cipher_rsa = PKCS1_OAEP.new(self.private_key)
        session_key = cipher_rsa.decrypt(enc_session_key)

        file_data = self.sym_enc.decrypt(nonce, ciphertext, tag, session_key)

        if self.asym_enc.verify_signature(file_data, signature, self.sender_public_key):
            return file_data
        else:
            raise ValueError("签名验证失败")