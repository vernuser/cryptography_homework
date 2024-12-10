import base64
from encryption_utils import SymmetricEncryption, AsymmetricEncryption, calculate_file_hash

class Receiver:
    def __init__(self, private_key):
        self.private_key = private_key

    def receive_file(self, encoded_data_packet):
        decoded_data_packet = base64.b64decode(encoded_data_packet)

        nonce = decoded_data_packet[:16]
        ciphertext = decoded_data_packet[16:-256-64]
        tag = decoded_data_packet[-256-64:-256]
        encrypted_symmetric_key = decoded_data_packet[-256:]
        original_hash = decoded_data_packet[-256-64:-256]  # 保持为字节

        asymmetric_encryption = AsymmetricEncryption()
        decrypted_symmetric_key = asymmetric_encryption.decrypt_with_private_key(encrypted_symmetric_key)

        symmetric_encryption = SymmetricEncryption()
        decrypted_file_data = symmetric_encryption.decrypt(nonce, ciphertext, tag, decrypted_symmetric_key)

        # Recalculate hash of decrypted file data
        received_file_hash = calculate_file_hash(decrypted_file_data).encode()

        if received_file_hash == original_hash:
            print("文件传输成功，文件完整性验证通过。")
        else:
            print("文件传输失败，文件可能已被篡改。")

        return decrypted_file_data
