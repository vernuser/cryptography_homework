import os
import json
import base64
import socket
from utils import aes_encrypt, rsa_encrypt, generate_signature, load_key

def send_file(filename, receiver_ip, receiver_port, receiver_public_key, sender_private_key):
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

    # 使用 Base64 对所有数据进行编码
    data_packet = {
        'nonce': base64.b64encode(nonce).decode(),
        'ciphertext': base64.b64encode(ciphertext).decode(),
        'tag': base64.b64encode(tag).decode(),
        'encrypted_key': base64.b64encode(encrypted_aes_key).decode(),
        'signature': base64.b64encode(signature).decode(),
        'filename': os.path.basename(filename)
    }

    # 转换为 JSON 格式
    data_packet_json = json.dumps(data_packet)

    # 建立网络连接并发送数据
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((receiver_ip, receiver_port))
        s.sendall(data_packet_json.encode('utf-8'))
        print("文件已发送！")

if __name__ == "__main__":
    # 加载密钥
    receiver_public_key = load_key('receiver_public.pem')
    sender_private_key = load_key('sender_private.pem')

    # 文件路径和接收方信息
    filename = '1.txt'
    receiver_ip = '192.168.98.130'  # 替换为接收方的IP地址
    receiver_port = 12345

    send_file(filename, receiver_ip, receiver_port, receiver_public_key, sender_private_key)
