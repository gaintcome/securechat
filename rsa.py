# import argparse
# import os
import sys
# from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives import padding as sympadding
from cryptography.hazmat.primitives.asymmetric import padding 
# from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key
import base64
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.exceptions import InvalidSignature


		
def loadPublickey(pk_file):
	try:
		public_key = None
		with open(pk_file, 'rb') as f:
			public_key = load_pem_public_key(f.read(), backend=default_backend())
		return public_key
	except:
		print "Error while loading public key"
	

def loadPrivatekey(pr_file):
	try:
		private_key = None
		with open(pr_file, "rb") as key_file:
			private_key = load_pem_private_key(key_file.read(),password=None, backend=default_backend())
		return private_key
	except: 
		print "error while loading the private key"


#RSA Encryption with given public key
#Inputs--> msg, and public key
#Returns the ciphertext
def rsaen(msg, public_key):
	ciphertext = public_key.encrypt(
	     msg,
	     padding.OAEP(
	         mgf=padding.MGF1(algorithm=hashes.SHA1()),
	         algorithm=hashes.SHA1(),
	         label=None
	     )
	 )
	return ciphertext

#RSA Decryption with given private key. It is assumed that only and only the receiver has access to the private key
#Inputs--> ciphertext and private_key
#Returns the plaintext
def rsade(cipher, private_key):
	try:
		plaintext = private_key.decrypt(
			cipher,
			padding.OAEP(
				mgf=padding.MGF1(algorithm=hashes.SHA1()),
				algorithm=hashes.SHA1(),
				label=None
				)
			)
		return plaintext	
	except ValueError as e:
		print 'Error while decrypting with RSA' + str(e)
		sys.exit(0)
	except AttributeError as a:
		print "algorithm parameters chosen are not recognised" + str(a)
		sys.exit(0)
	except:
		print "Error occured while decrypting with RSA"
		sys.exit(0) 
'''
pk = loadPublickey('pubkey.pub')
enc = rsaen("salam", pk)
print "cipher", enc

pr = loadPrivatekey('privatekey.pem')
dec = rsade(enc, pr)
print "plain ", dec'''