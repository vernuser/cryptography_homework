import os
import json
from utils import aes_encrypt, rsa_encrypt, generate_signature, load_key

def send_file(filename, receiver_public_key, sender_private_key):
    # 读取文件内容
    with open(filename, 'rb') as f:
        file_data = f.read()

    # 生成随机AES密钥
    aes_key = os.urandom(16)

    # 加密文件
    nonce, ciphertext, tag = aes_encrypt(file_data, aes_key)

    # 使用接收方公钥加密AES密钥
    encrypted_aes_key = rsa_encrypt(aes_key, receiver_public_key)

    # 生成数字签名（针对原始文件内容）
    signature = generate_signature(sender_private_key, file_data)

    # 封装数据包
    data_packet = {
        'nonce': base64.b64encode(nonce).decode(),
        'ciphertext': base64.b64encode(ciphertext).decode(),
        'tag': base64.b64encode(tag).decode(),
        'encrypted_key': base64.b64encode(encrypted_aes_key).decode(),
        'signature': base64.b64encode(signature).decode(),
        'filename': os.path.basename(filename)
    }

    # 保存数据包到文件
    with open('data_packet.json', 'w') as f:
        json.dump(data_packet, f)

    print("文件已加密并发送。")

if __name__ == "__main__":
    receiver_public_key = load_key('receiver_public.pem')
    sender_private_key = load_key('sender_private.pem')
    send_file('example.txt', receiver_public_key, sender_private_key)

