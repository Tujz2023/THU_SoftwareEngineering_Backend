from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import base64

SECRET_KEY = b"/Fz7Ta1nLj9wQiuJ"  # 16字节密钥
FIXED_IV = b"\x00" * 16  # 固定 IV，16 字节全零

def encrypt_text(text):
    cipher = Cipher(algorithms.AES(SECRET_KEY), modes.CBC(FIXED_IV), backend=default_backend())
    encryptor = cipher.encryptor()

    # **使用 PKCS#7 填充**
    padder = padding.PKCS7(128).padder()
    padded_text = padder.update(text.encode("utf-8")) + padder.finalize()

    encrypted = encryptor.update(padded_text) + encryptor.finalize()
    return base64.b64encode(encrypted).decode("utf-8")

def decrypt_text(encrypted_text):
    cipher = Cipher(algorithms.AES(SECRET_KEY), modes.CBC(FIXED_IV), backend=default_backend())
    decryptor = cipher.decryptor()

    encrypted_bytes = base64.b64decode(encrypted_text)
    decrypted_padded = decryptor.update(encrypted_bytes) + decryptor.finalize()

    # **移除 PKCS#7 填充**
    unpadder = padding.PKCS7(128).unpadder()
    decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
    
    return decrypted.decode("utf-8")



# text = 'my name is tujz'
# print(encrypt_text("test"))
# print(list(SECRET_KEY))
# print(decrypt_text(encrypt_text(text)))
# print(decrypt_text("rQ3hmX3MaeucnOtO5nEYHM/sXXaz7wYbA0melosMZgQ="))