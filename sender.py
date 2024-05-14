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
from Crypto.Random import get_random_bytes
# --------------------------------------------------------------------------------/
# Generates an RSA key pair (private and public key) with a key size of 2048 bits.
# Returns the private key and public key in binary format.
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key
# --------------------------------------------------------------------------------------
# Writes the RSA private and public keys to a specified file.
# Args:
# private_key: Binary private key to write.
# public_key: Binary public key to write.
# filename: The filename where the keys will be saved.
def write_keys_to_file(private_key, public_key, filename):

    with open(filename, 'wb') as f:
        f.write(private_key)
        f.write(b'\n')  # New line separator between private and public keys
        f.write(public_key)
# --------------------------------------------------------------------------------------
# Reads the public RSA key from a file.
# Args:
# filename: The filename from which to read the public key.
# Returns:
# The imported public RSA key.
def read_public_key(filename):

    with open(filename, 'rb') as f:
        key_data = f.read()
    public_key_data = key_data.split(b'-----BEGIN PUBLIC KEY-----')[1]
    return RSA.import_key(b'-----BEGIN PUBLIC KEY-----' + public_key_data)
# --------------------------------------------------------------------------------------
# Encrypts a message using AES in EAX mode.
# Args:
# message: The plaintext message to encrypt.
# key: The AES key.
# Returns:
# nonce: The nonce used during the encryption. Required for decryption.
# ciphertext: The encrypted message.
# tag: The tag used to verify the integrity and authenticity of the message.
def encrypt_message_aes(message, key):

    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
    return nonce, ciphertext, tag
# --------------------------------------------------------------------------------------
# Encrypts an AES key using RSA.
# Args:
# aes_key: The AES key to encrypt.
# public_key: The receiver's public RSA key.
# Returns:
# The encrypted AES key.
def encrypt_aes_key_with_rsa(aes_key, public_key):

    cipher_rsa = PKCS1_OAEP.new(public_key)
    enc_key = cipher_rsa.encrypt(aes_key)
    return enc_key
# --------------------------------------------------------------------------------------
# Creates a signature for a given ciphertext using RSA-PSS.
# Args:
# ciphertext: The ciphertext to sign.
# private_key: The sender's private RSA key.
# Returns:
# The signature of the ciphertext.
def create_signature(ciphertext, private_key):

    h = SHA256.new(ciphertext)
    signer = pss.new(RSA.import_key(private_key))
    signature = signer.sign(h)
    return signature
# --------------------------------------------------------------------------------------

# Generate and save RSA keys for both sender and receiver
sender_private, sender_public = generate_rsa_keys()
receiver_private, receiver_public = generate_rsa_keys()
write_keys_to_file(sender_private, sender_public, 'sender_keys.pem')
write_keys_to_file(receiver_private, receiver_public, 'receiver_keys.pem')

# Read the public RSA key of the receiver
receiver_pub_key = read_public_key('receiver_keys.pem')

# Allow the sender to input their own message
message = input("Enter your message: ")

# Generate a random AES key
aes_key = get_random_bytes(16)

# Encrypt the message with AES
nonce, ciphertext, tag = encrypt_message_aes(message, aes_key)

# Encrypt the AES key with the receiver's RSA public key
encrypted_aes_key = encrypt_aes_key_with_rsa(aes_key, receiver_pub_key)

# Create a signature for the ciphertext
signature = create_signature(ciphertext, sender_private)

# Write all transmitted data to a file
with open('Transmitted_Data.txt', 'wb') as f:
    f.write(encrypted_aes_key)
    f.write(nonce)
    f.write(ciphertext)
    f.write(tag)
    f.write(signature)

print("Data encrypted and written to 'Transmitted_Data.txt'")
