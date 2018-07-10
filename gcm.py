import os
import base64

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)

def aes_encrypt(key, plaintext, associated_data):
    # Generate a random 96-bit IV.
    iv = os.urandom(12)

    # Construct an AES-GCM Cipher object with the given key and a
    # randomly generated IV.
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()

    # associated_data will be authenticated but not encrypted,
    # it must also be passed in on decryption.
    encryptor.authenticate_additional_data(associated_data)

    # Encrypt the plaintext and get the associated ciphertext.
    # GCM does not require padding.
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    
    #iv = iv.encode('utf-8')
    #ciphertext = ciphertext.encode('utf-8')
    tag = encryptor.tag
    return (iv, ciphertext, tag)

def aes_decrypt(key, associated_data, iv, ciphertext, tag):
    
    # Construct a Cipher object, with the key, iv, and additionally the
    # GCM tag used for authenticating the message.


    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()

    # We put associated_data back in or the tag will fail to verify
    # when we finalize the decryptor.
    decryptor.authenticate_additional_data(associated_data)

    # Decryption gets us the authenticated plaintext.
    # If the tag does not match an InvalidTag exception will be raised.
    return decryptor.update(ciphertext) + decryptor.finalize()
'''
key = os.urandom(32)
print "type Os.random is ", type(key)
iv, ciphertext, tag = aes_encrypttt( key, b"a secret message!", b"authenticated but not encrypted payload" )
#print ciphertext
print(aes_decrypttt(
    key,
    b"authenticated but not encrypted payload",
    iv,
    ciphertext,
    tag
))'''