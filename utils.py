from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import base64
import os


# 生成RSA密钥对
def generate_rsa_keypair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key


# 保存密钥到文件
def save_key(filename, key):
    with open(filename, 'wb') as f:
        f.write(key)


# 加载密钥
def load_key(filename):
    with open(filename, 'rb') as f:
        return f.read()


# AES加密文件内容
def aes_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce, ciphertext, tag


# AES解密文件内容
def aes_decrypt(nonce, ciphertext, tag, key):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)


# 使用RSA加密对称密钥
def rsa_encrypt(data, public_key):
    cipher = PKCS1_OAEP.new(RSA.import_key(public_key))
    return cipher.encrypt(data)


# 使用RSA解密对称密钥
def rsa_decrypt(data, private_key):
    cipher = PKCS1_OAEP.new(RSA.import_key(private_key))
    return cipher.decrypt(data)


# 生成数字签名
def generate_signature(private_key, data):
    key = RSA.import_key(private_key)
    h = SHA256.new(data)
    signature = pkcs1_15.new(key).sign(h)
    return signature


# 验证数字签名
def verify_signature(public_key, data, signature):
    key = RSA.import_key(public_key)
    h = SHA256.new(data)
    try:
        pkcs1_15.new(key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False
