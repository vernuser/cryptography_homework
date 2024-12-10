from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
import json
import base64
from encryption_utils import AsymmetricEncryption, SymmetricEncryption

class Sender:
    def __init__(self, filepath, receiver_public_key, sender_private_key):
        self.filepath = filepath
        self.receiver_public_key = RSA.import_key(receiver_public_key)
        self.sender_private_key = RSA.import_key(sender_private_key)
        self.asym_enc = AsymmetricEncryption()
        self.sym_enc = SymmetricEncryption()

    def send_file(self):
        with open(self.filepath, 'rb') as f:
            file_data = f.read()

        session_key = get_random_bytes(16)
        cipher_rsa = PKCS1_OAEP.new(self.receiver_public_key)
        enc_session_key = cipher_rsa.encrypt(session_key)

        nonce, ciphertext, tag = self.sym_enc.encrypt(file_data, session_key)
        signature = self.asym_enc.sign_data(file_data)

        data_to_send = {
            'enc_session_key': base64.b64encode(enc_session_key).decode(),
            'nonce': base64.b64encode(nonce).decode(),
            'tag': base64.b64encode(tag).decode(),
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'signature': base64.b64encode(signature).decode()
        }

        return json.dumps(data_to_send)