from encryption_utils import AsymmetricEncryption, SymmetricEncryption
from Crypto.Random import get_random_bytes

def run_example():
    # 生成接收方的密钥对
    receiver_asymmetric = AsymmetricEncryption()
    receiver_public_key = receiver_asymmetric.get_public_key()
    receiver_private_key = receiver_asymmetric.get_private_key()

    # 生成对称密钥
    symmetric_key = get_random_bytes(16)  # AES 128 位密钥

    # 使用接收方的公钥加密对称密钥
    encrypted_symmetric_key = receiver_asymmetric.encrypt_with_public_key(symmetric_key, receiver_public_key)

    # 读取文件内容
    with open('example.txt', 'rb') as file:
        file_data = file.read()

    # 使用对称密钥加密文件内容
    symmetric_encryption = SymmetricEncryption()
    nonce, ciphertext, tag = symmetric_encryption.encrypt(file_data, symmetric_key)

    # 模拟发送和接收
    encoded_packet = (encrypted_symmetric_key, nonce, ciphertext, tag)

    # 使用接收方私钥解密对称密钥
    decrypted_symmetric_key = receiver_asymmetric.decrypt_with_private_key(encoded_packet[0])

    # 使用解密后的对称密钥解密文件内容
    decrypted_data = symmetric_encryption.decrypt(encoded_packet[1], encoded_packet[2], encoded_packet[3], decrypted_symmetric_key)
    print("Decrypted Data:", decrypted_data.decode('utf-8'))

if __name__ == "__main__":
    run_example()
