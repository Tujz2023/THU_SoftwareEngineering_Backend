from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import os

# SECRET_KEY = "my-secret-key123".encode("utf-8")  # 密钥
SECRET_KEY = "/Fz7Ta1nLj9wQiuJ".encode("utf-8")
FIXED_IV = b"\x00" * 16  # 固定 IV，16 字节全零

def encrypt_text(text):
    cipher = Cipher(algorithms.AES(SECRET_KEY), modes.CBC(FIXED_IV), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_text = text.encode("utf-8").ljust(16, b"\x00")  # 填充到 16 字节
    encrypted = encryptor.update(padded_text) + encryptor.finalize()
    return base64.b64encode(encrypted).decode("utf-8")

def decrypt_text(encrypted_text):
    cipher = Cipher(algorithms.AES(SECRET_KEY), modes.CBC(FIXED_IV), backend=default_backend())
    decryptor = cipher.decryptor()
    encrypted_bytes = base64.b64decode(encrypted_text)
    decrypted = decryptor.update(encrypted_bytes) + decryptor.finalize()
    return decrypted.rstrip(b"\x00").decode("utf-8")  # 去掉填充

# text = 'my name is tujz'
# print(encrypt_text("test"))
# print(decrypt_text(encrypt_text(text)))
# print(decrypt_text("FvZr+sTahpyeHLw9hiH61w=="))