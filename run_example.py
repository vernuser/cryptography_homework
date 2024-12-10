import socket
import threading
from Crypto.PublicKey import RSA
from sender import Sender
from receiver import Receiver

class FileTransferApp:
    def __init__(self, host, port, role):
        self.host = host
        self.port = port
        self.role = role
        self.private_key = None
        self.public_key = None
        self.running = True

    def generate_keys(self):
        key = RSA.generate(2048)
        self.private_key = key.export_key()
        self.public_key = key.publickey().export_key()
        if self.role == 'sender':
            priv_filename = 'send_private.pem'
            pub_filename = 'send_public.pem'
        else:
            priv_filename = 'receive_private.pem'
            pub_filename = 'receive_public.pem'
        with open(priv_filename, 'wb') as priv_file:
            priv_file.write(self.private_key)
        with open(pub_filename, 'wb') as pub_file:
            pub_file.write(self.public_key)
        print(f"密钥生成成功，已保存到 {priv_filename} 和 {pub_filename}。")

    def load_keys(self):
        if self.role == 'sender':
            priv_filename = 'send_private.pem'
            pub_filename = 'send_public.pem'
        else:
            priv_filename = 'receive_private.pem'
            pub_filename = 'receive_public.pem'
        try:
            with open(priv_filename, 'rb') as priv_file:
                self.private_key = priv_file.read()
            with open(pub_filename, 'rb') as pub_file:
                self.public_key = pub_file.read()
            print("密钥加载成功。")
        except FileNotFoundError:
            print("密钥文件未找到，请先生成密钥。")

    def load_public_key(self, filepath):
        try:
            with open(filepath, 'rb') as pub_file:
                return pub_file.read()
        except FileNotFoundError:
            print(f"公钥文件 {filepath} 未找到。")
            return None

    def send_file(self, filepath, receiver_host, receiver_public_key_path):
        receiver_public_key = self.load_public_key(receiver_public_key_path)
        if receiver_public_key is None:
            return

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((receiver_host, self.port))

                sender = Sender(filepath, receiver_public_key, self.private_key)
                data_to_send = sender.send_file()
                if data_to_send is None:
                    print("文件加密失败，未发送。")
                    return

                s.sendall(data_to_send.encode())
                print("文件发送成功。")
        except Exception as e:
            print(f"发送文件时发生错误: {e}")

    def receive_file(self, sender_public_key_path):
        sender_public_key = self.load_public_key(sender_public_key_path)
        if sender_public_key is None:
            return

        try:
            if self.private_key is None:
                raise ValueError("未生成私钥，请先生成密钥。")

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind((self.host, self.port))
                s.listen()
                print(f"服务器正在 {self.host}:{self.port} 监听...")
                conn, addr = s.accept()
                with conn:
                    print(f"已连接到 {addr}")
                    data = b''
                    while True:
                        packet = conn.recv(1024)
                        if not packet:
                            break
                        data += packet

                    receiver = Receiver(self.private_key, sender_public_key)
                    decrypted_data = receiver.receive_file(data.decode())

                    if decrypted_data is not None:
                        with open('received_file', 'wb') as f:
                            f.write(decrypted_data)
                        print("文件接收并解密成功。")
                    else:
                        print("解密失败，文件未保存。")
        except ValueError as ve:
            print(f"值错误: {ve}")
        except Exception as e:
            print(f"接收文件时发生错误: {e}")

    def run(self):
        while self.running:
            command = input("输入 'generate_keys' 生成密钥，'load_keys' 加载密钥，'send' 发送文件，'receive' 接收文件，或 'exit' 退出程序: ").strip().lower()
            if command == 'generate_keys':
                self.generate_keys()
            elif command == 'load_keys':
                self.load_keys()
            elif command == 'send':
                filepath = input("输入要发送的文件路径: ")
                receiver_host = input("输入接收方的计算机IP地址: ")
                receiver_public_key_path = input("输入接收方的公钥文件路径: ")
                threading.Thread(target=self.send_file, args=(filepath, receiver_host, receiver_public_key_path)).start()
            elif command == 'receive':
                sender_public_key_path = input("输入发送方的公钥文件路径: ")
                threading.Thread(target=self.receive_file, args=(sender_public_key_path,)).start()
            elif command == 'exit':
                self.running = False
                print("正在退出程序。")
                break
            else:
                print("无效的命令。")

if __name__ == "__main__":
    role = input("输入角色 ('sender' 或 'receiver'): ").strip().lower()
    app = FileTransferApp(host='0.0.0.0', port=65432, role=role)
    app.run()