from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
import base64



def generateMAC( msg, key):
	h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
	h.update(msg)
	return base64.b64encode(h.finalize())
