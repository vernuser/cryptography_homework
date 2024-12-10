import json
import base64
import socket
from utils import aes_decrypt, rsa_decrypt, verify_signature, load_key

def receive_file(port, receiver_private_key, sender_public_key):
    # 启动服务监听
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', port))
        s.listen(1)
        print(f"接收方正在监听端口 {port}...")

        conn, addr = s.accept()
        print(f"来自 {addr} 的连接已建立！")

        with conn:
            # 接收数据
            data = conn.recv(65536)  # 最大接收 64KB 数据
            data_packet = json.loads(data.decode('utf-8'))

            # 解码 Base64 数据
            nonce = base64.b64decode(data_packet['nonce'])
            ciphertext = base64.b64decode(data_packet['ciphertext'])
            tag = base64.b64decode(data_packet['tag'])
            encrypted_key = base64.b64decode(data_packet['encrypted_key'])
            signature = base64.b64decode(data_packet['signature'])
            filename = data_packet['filename']

            # 使用接收方私钥解密AES密钥
            aes_key = rsa_decrypt(encrypted_key, receiver_private_key)

            # 使用AES密钥解密文件内容
            try:
                file_data = aes_decrypt(nonce, ciphertext, tag, aes_key)

                # 验证签名
                if verify_signature(sender_public_key, file_data, signature):
                    print("签名验证成功，文件未被篡改！")
                    # 保存解密后的文件
                    with open(f"received_{filename}", 'wb') as f:
                        f.write(file_data)
                    print(f"文件已保存为 received_{filename}")
                else:
                    print("签名验证失败，文件可能被篡改！")
            except Exception as e:
                print(f"文件解密或验证过程中出错：{e}")

if __name__ == "__main__":
    # 加载密钥
    receiver_private_key = load_key('receiver_private.pem')
    sender_public_key = load_key('sender_public.pem')

    # 监听端口
    port = 12345
    receive_file(port, receiver_private_key, sender_public_key)
