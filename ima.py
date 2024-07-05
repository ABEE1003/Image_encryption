
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
import base64
import os

# AES encryption/decryption
def aes_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    iv = cipher.iv
    return base64.b64encode(iv + ct_bytes).decode('utf-8')

def aes_decrypt(enc_data, key):
    enc_data = base64.b64decode(enc_data)
    iv = enc_data[:AES.block_size]
    ct = enc_data[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size)

# RSA encryption/decryption
def rsa_encrypt(data, public_key):
    cipher_rsa = PKCS1_OAEP.new(public_key)
    return cipher_rsa.encrypt(data)

def rsa_decrypt(enc_data, private_key):
    cipher_rsa = PKCS1_OAEP.new(private_key)
    return cipher_rsa.decrypt(enc_data)

# Padding functions for AES
def pad(data, block_size):
    padding_len = block_size - len(data) % block_size
    padding = bytes([padding_len]) * padding_len
    return data + padding

def unpad(data, block_size):
    padding_len = data[-1]
    return data[:-padding_len]

# Generate AES key
aes_key = get_random_bytes(32)

# Generate RSA keys
rsa_key = RSA.generate(2048)
private_key = rsa_key.export_key()
public_key = rsa_key.publickey().export_key()

# Encrypt AES key with RSA public key
encrypted_aes_key = rsa_encrypt(aes_key, RSA.import_key(public_key))

# Example image encryption
with open('image.jpg', 'rb') as image_file:
    image_data = image_file.read()

encrypted_image = aes_encrypt(image_data, aes_key)

# Example image decryption
decrypted_image = aes_decrypt(encrypted_image, aes_key)

with open('decrypted_image.jpg', 'wb') as image_file:
    image_file.write(decrypted_image)

# Ensure integrity
image_hash = SHA256.new(image_data).hexdigest()
decrypted_image_hash = SHA256.new(decrypted_image).hexdigest()

assert image_hash == decrypted_image_hash, "Integrity check failed!"
input("image.jpg has been decrypted successfully")
