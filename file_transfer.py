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

    def send_file(self, filepath, receiver_host):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((receiver_host, self.port))
                sender = Sender(filepath, receiver_public_key=self.public_key)
                data_to_send = sender.send_file()
                s.sendall(data_to_send)
                print("File sent successfully.")
        except Exception as e:
            print(f"An error occurred while sending the file: {e}")

    def receive_file(self):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind((self.host, self.port))
                s.listen()
                print(f"Server listening on {self.host}:{self.port}")
                conn, addr = s.accept()
                with conn:
                    print(f"Connected by {addr}")
                    data = b''
                    while True:
                        packet = conn.recv(1024)
                        if not packet:
                            break
                        data += packet
                    receiver = Receiver(private_key=self.private_key)
                    decrypted_data = receiver.receive_file(data)
                    if decrypted_data:
                        # Save or process the decrypted file data
                        with open('received_file', 'wb') as f:
                            f.write(decrypted_data)
                        print("File received and decrypted successfully.")
        except Exception as e:
            print(f"An error occurred while receiving the file: {e}")

    def run(self):
        while self.running:
            command = input("Enter 'generate_keys' to generate keys, 'send' to send a file, 'receive' to receive a file, or 'exit' to quit: ").strip().lower()
            if command == 'generate_keys':
                self.generate_keys()
                print("Keys generated successfully.")
            elif command == 'send':
                filepath = input("Enter the path of the file to send: ")
                receiver_host = input("Enter the receiver's host (IP address): ")
                threading.Thread(target=self.send_file, args=(filepath, receiver_host)).start()
            elif command == 'receive':
                threading.Thread(target=self.receive_file).start()
            elif command == 'exit':
                self.running = False
                print("Exiting application.")
                break
            else:
                print("Invalid command.")

if __name__ == "__main__":
    app = FileTransferApp(host='0.0.0.0', port=65432)
    app.run()
