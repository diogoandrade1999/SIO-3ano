import os
import base64

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID


backend = default_backend()

class MyRSA:
	def __init__(self):
		self.prikey = None
		self.pubKey = None
		self.nonce = None

	def get_nonce(self):
		self.nonce = os.urandom(16)
		return self.nonce

	def set_nonce(self, n):
		self.nonce = n

	def generate_keys(self):
		self.prikey = rsa.generate_private_key(public_exponent=65537, 
												key_size=2048,
												backend=backend)
		self.pubKey = self.prikey.public_key()

	def export_key(self):
		pubKeyPEM = self.pubKey.public_bytes(encoding=serialization.Encoding.PEM,
											format=serialization.PublicFormat.SubjectPublicKeyInfo)
		return base64.b64encode(pubKeyPEM).decode('utf-8')

	def import_key(self, key):
		self.pubKey = serialization.load_pem_public_key(base64.b64decode(key.encode('utf-8')), backend)

	def encryption(self, password):
		message = self.nonce + password
		return self.pubKey.encrypt(message,
									padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
												algorithm=hashes.SHA256(), label=None))

	def decryption(self, cipher_text):
		return self.prikey.decrypt(cipher_text,
									padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
												algorithm=hashes.SHA256(), label=None))

	def calc_digest(self, password):
		message = self.nonce + password
		hasher = hashes.Hash(hashes.SHA256(), backend)
		hasher.update(message)
		return hasher.finalize()

	def signature(self, password):
		digest = self.calc_digest(password)
		return self.prikey.sign(digest,
								padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
											salt_length=padding.PSS.MAX_LENGTH),
											utils.Prehashed(hashes.SHA256()))

	def verification(self, password, signature):
		digest = self.calc_digest(password)
		try:
			self.pubKey.verify(signature, 
								digest, 
								padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
											salt_length=padding.PSS.MAX_LENGTH),
											utils.Prehashed(hashes.SHA256()))
		except Exception:
			return False, 'The signature is not authentic.'
		return True, 'The signature is authentic.'
