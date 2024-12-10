from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

class AsymmetricEncryption:
    def __init__(self):
        self.key_pair = RSA.generate(2048)

    def get_public_key(self):
        return self.key_pair.publickey()

    def get_private_key(self):
        return self.key_pair

    def encrypt_with_public_key(self, data, public_key):
        cipher_rsa = PKCS1_OAEP.new(public_key)
        return cipher_rsa.encrypt(data)

    def decrypt_with_private_key(self, encrypted_data):
        cipher_rsa = PKCS1_OAEP.new(self.key_pair)
        return cipher_rsa.decrypt(encrypted_data)

    def sign_data(self, data):
        h = SHA256.new(data)
        signature = pkcs1_15.new(self.key_pair).sign(h)
        return signature

    def verify_signature(self, data, signature, public_key):
        h = SHA256.new(data)
        try:
            pkcs1_15.new(public_key).verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False

class SymmetricEncryption:
    def encrypt(self, data, key):
        cipher_aes = AES.new(key, AES.MODE_GCM)
        nonce = cipher_aes.nonce
        ciphertext, tag = cipher_aes.encrypt_and_digest(data)
        return nonce, ciphertext, tag

    def decrypt(self, nonce, ciphertext, tag, key):
        cipher_aes = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher_aes.decrypt_and_verify(ciphertext, tag)