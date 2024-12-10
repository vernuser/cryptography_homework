from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
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

class SymmetricEncryption:
    def encrypt(self, data, key):
        cipher_aes = AES.new(key, AES.MODE_GCM)
        nonce = cipher_aes.nonce
        ciphertext, tag = cipher_aes.encrypt_and_digest(data)
        return nonce, ciphertext, tag

    def decrypt(self, nonce, ciphertext, tag, key):
        cipher_aes = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher_aes.decrypt_and_verify(ciphertext, tag)

def calculate_file_hash(file_data):
    hash_obj = SHA256.new(file_data)
    return hash_obj.digest()
