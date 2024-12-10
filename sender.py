import base64
from Crypto.Random import get_random_bytes  # 确保导入随机字节生成函数
from encryption_utils import SymmetricEncryption, AsymmetricEncryption, calculate_file_hash

class Sender:
    def __init__(self, filepath, receiver_public_key):
        self.filepath = filepath
        self.receiver_public_key = receiver_public_key

    def send_file(self):
        with open(self.filepath, 'rb') as f:
            file_data = f.read()

        symmetric_key = get_random_bytes(16)
        symmetric_encryption = SymmetricEncryption()
        nonce, ciphertext, tag = symmetric_encryption.encrypt(file_data, symmetric_key)

        file_hash = calculate_file_hash(file_data)

        asymmetric_encryption = AsymmetricEncryption()
        encrypted_symmetric_key = asymmetric_encryption.encrypt_with_public_key(symmetric_key, self.receiver_public_key)

        encoded_data_packet = base64.b64encode(nonce + ciphertext + tag + encrypted_symmetric_key + file_hash.encode())

        return encoded_data_packet
