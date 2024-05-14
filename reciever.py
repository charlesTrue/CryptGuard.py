# *******************************************************************************
# Programmer: Charles Trouilliere
# Class:CS4600 Cryptography & InfoSec | Dr.Tingting Chen
# Date Completed: 05/10/24
# Project Description: The goal of this project is to design a secure communication system
# between two parties that ensures confidentiality, integrity, and authenticity of messages.
# The system consists of two Python scripts, `sender.py` and `receiver.py`, which simulate
# the roles of a message sender and receiver respectively.
# *******************************************************************************
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import pss
import os
# --------------------------------------------------------------------------------/
# Reads and imports the private RSA key from a specified file.
# Args: filename: The file name from which to read the private RSA key.
# Returns:The imported private RSA key.
def read_private_key(filename):
    with open(filename, 'rb') as f:
        key_data = f.read()
    private_key_data = key_data.split(b'-----END RSA PRIVATE KEY-----')[0] + b'-----END RSA PRIVATE KEY-----'
    return RSA.import_key(private_key_data)
# --------------------------------------------------------------------------------------
# Decrypts an AES key that was encrypted with the RSA public key using the RSA private key.
# Args:
# encrypted_key: The encrypted AES key. private_key: The RSA private key to decrypt the AES key.
# Returns: The decrypted AES key.
def decrypt_aes_key_with_rsa(encrypted_key, private_key):

    cipher_rsa = PKCS1_OAEP.new(private_key)
    aes_key = cipher_rsa.decrypt(encrypted_key)
    return aes_key
# --------------------------------------------------------------------------------------
# Decrypts the AES encrypted message using the provided AES key, nonce, and tag.
# Args:
# nonce: The nonce used during the encryption process.
# ciphertext: The encrypted message data.
# tag: The integrity tag that was appended during encryption.
# aes_key: The AES key to decrypt the message.
# Returns: The decrypted plaintext message as a string.
def decrypt_message_aes(nonce, ciphertext, tag, aes_key):

    cipher = AES.new(aes_key, AES.MODE_EAX, nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    return data.decode('utf-8')
# --------------------------------------------------------------------------------------
# Verifies the signature of the ciphertext using the sender's public RSA key.
# Args:
# ciphertext: The ciphertext whose integrity is to be verified.
# signature: The signature to verify.
# public_key: The public RSA key used to verify the signature.
# Returns:
# True if the verification is successful, False otherwise.
def verify_signature(ciphertext, signature, public_key):

    h = SHA256.new(ciphertext)
    verifier = pss.new(public_key)
    try:
        verifier.verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False
# --------------------------------------------------------------------------------------
# Read the private RSA key of the receiver
receiver_private_key = read_private_key('receiver_keys.pem')

# Read the transmitted data
with open('Transmitted_Data.txt', 'rb') as f:
    encrypted_aes_key = f.read(256)  # Expected size based on RSA key length
    nonce = f.read(16)  # AES nonce size
    ciphertext_length = os.path.getsize('Transmitted_Data.txt') - 256 - 16 - 16 - 256
    ciphertext = f.read(ciphertext_length)
    tag = f.read(16)  # AES tag size
    signature = f.read(256)  # RSA signature size

# Decrypt the AES key
aes_key = decrypt_aes_key_with_rsa(encrypted_aes_key, receiver_private_key)

# Decrypt the message
try:
    message = decrypt_message_aes(nonce, ciphertext, tag, aes_key)
    print("Decrypted message:", message)
except ValueError as e:
    print("Decryption failed:", e)

# Read sender's public key to verify signature
sender_public_key = RSA.import_key(open('sender_keys.pem', 'rb').read().split(b'\n-----END RSA PRIVATE KEY-----\n')[1])

# Verify signature
if verify_signature(ciphertext, signature, sender_public_key):
    print("Signature verified successfully. Message integrity confirmed.")
else:
    print("Signature verification failed. The message may have been tampered with.")
