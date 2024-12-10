import socket
import threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256


class FileTransferApp:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.private_key = None
        self.public_key = None
        self.running = True

    def generate_keys(self):
        key = RSA.generate(2048)
        self.private_key = key.export_key()
        self.public_key = key.publickey().export_key()
        print("密钥生成成功。")

    def send_file(self, filepath, receiver_host):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((receiver_host, self.port))
                sender = Sender(filepath, receiver_public_key=self.public_key)
                data_to_send = sender.send_file()
                s.sendall(data_to_send)
                print("文件发送成功。")
        except Exception as e:
            print(f"发送文件时发生错误: {e}")

    def receive_file(self):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind((self.host, self.port))
                s.listen()
                print(f"服务器正在监听 {self.host}:{self.port}")
                conn, addr = s.accept()
                with conn:
                    print(f"已连接 {addr}")
                    data = b''
                    while True:
                        packet = conn.recv(1024)
                        if not packet:
                            break
                        data += packet
                    receiver = Receiver(private_key=self.private_key)
                    decrypted_data = receiver.receive_file(data)
                    if decrypted_data:
                        # 保存或处理解密后的文件数据
                        with open('received_file', 'wb') as f:
                            f.write(decrypted_data)
                        print("文件接收并解密成功。")
        except Exception as e:
            print(f"接收文件时发生错误: {e}")

    def run(self):
        while self.running:
            command = input("输入 'generate_keys' 生成密钥，'send' 发送文件，'receive' 接收文件，或 'exit' 退出程序: ").strip().lower()
            if command == 'generate_keys':
                self.generate_keys()
            elif command == 'send':
                filepath = input("输入要发送的文件路径: ")
                receiver_host = input("输入接收方的计算机IP地址: ")
                threading.Thread(target=self.send_file, args=(filepath, receiver_host)).start()
            elif command == 'receive':
                threading.Thread(target=self.receive_file).start()
            elif command == 'exit':
                self.running = False
                print("正在退出程序。")
                break
            else:
                print("无效的命令。")

if __name__ == "__main__":
    app = FileTransferApp(host='0.0.0.0', port=65432)
    app.run()
