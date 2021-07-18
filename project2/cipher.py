import os
import base64

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding, load_der_public_key
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


backend = default_backend()


class MyCipher:
	def __init__(self, key_exchange, cipher_algorithm, mode, control, length):
		self._key_exchange = key_exchange
		self._cipher_algorithm = cipher_algorithm
		self._mode = mode
		self._control = control
		self._length = int(int(length)/8)
		self._salt = None
		self._private_key = None
		self._public_key = None
		self._key = None

	def make_keys(self):
		if self._key_exchange == 'DH':
			p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
			params_numbers = dh.DHParameterNumbers(p, 2)
			parameters = params_numbers.parameters(backend)
			# parameters = dh.generate_parameters(generator=2, key_size=512, backend=backend)
			self._private_key = parameters.generate_private_key()
		elif self._key_exchange == 'X25519':
			self._private_key = X25519PrivateKey.generate()
		# elif self._key_exchange == 'X448':
		else:
			self._private_key = X448PrivateKey.generate()
		self._public_key = self._private_key.public_key()

	def public_key(self):
		return base64.b64encode(self._public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo))\
			.decode('utf-8')

	def key(self, key):
		key = load_der_public_key(base64.b64decode(key.encode('utf-8')), backend)
		self._key = self._private_key.exchange(key)

	def derived_key(self):
		if self._control == 'SHA224':
			control = hashes.SHA224()
		if self._control == 'SHA256':
			control = hashes.SHA256()
		elif self._control == 'SHA384':
			control = hashes.SHA384()
		elif self._control == 'SHA512':
			control = hashes.SHA512()
		elif self._control == 'SHA512-224':
			control = hashes.SHA512_224()
		elif self._control == 'SHA3-224':
			control = hashes.SHA3_224()
		elif self._control == 'SHA3-256':
			control = hashes.SHA3_256()
		elif self._control == 'SHA3-384':
			control = hashes.SHA3_384()
		# elif self._control == 'SHA3-512':
		else:
			control = hashes.SHA3_512()
		return PBKDF2HMAC(
			algorithm=control,
			length=self._length,
			salt=self._salt,
			iterations=100000,
			backend=backend
		).derive(self._key)

	def make_cipher(self, tag=None):
		key = self.derived_key()
		# DO NOT IMPLEMENTED: ChaCha20[256], ARC4[256, 192, 128, 64]
		if self._cipher_algorithm == 'AES':
			algorithm = algorithms.AES(key)
		elif self._cipher_algorithm == '3DES':
			algorithm = algorithms.TripleDES(key)
		elif self._cipher_algorithm == 'Camellia':
			algorithm = algorithms.Camellia(key)
		elif self._cipher_algorithm == 'CAST5':
			algorithm = algorithms.CAST5(key)
		elif self._cipher_algorithm == 'SEED':
			algorithm = algorithms.SEED(key)
		elif self._cipher_algorithm == 'Blowfish':
			algorithm = algorithms.Blowfish(key)
		# elif self._cipher_algorithm == 'IDEA':
		else:
			algorithm = algorithms.IDEA(key)
		if self._mode == 'ECB':
			mode = modes.ECB()
		elif self._mode == 'CBC':
			mode = modes.CBC(self._salt)
		elif self._mode == 'CTR':
			mode = modes.CTR(self._salt)
		elif self._mode == 'OFB':
			mode = modes.OFB(self._salt)
		elif self._mode == 'GCM':
			mode = modes.GCM(self._salt, tag=tag)
		elif self._mode == 'CFB':
			mode = modes.CFB(self._salt)
		elif self._mode == 'CFB8':
			mode = modes.CFB8(self._salt)
		# Should be use only for disk encryption
		# elif self._mode == 'XTS':
		else:
			mode = modes.XTS(self._salt)
		return Cipher(algorithm, mode, backend=backend), key

	def encrypt_message(self, message):
		message = str(message).encode('utf-8')
		self._salt = os.urandom(16)
		cipher, key = self.make_cipher()
		bs = int(cipher.algorithm.block_size / 8)
		missing_bytes = bs - len(message) % bs
		if missing_bytes == 0:
			missing_bytes = bs
		padding = bytes([missing_bytes] * missing_bytes)
		message += padding
		encryptor = cipher.encryptor()
		cryptogram = encryptor.update(message) + encryptor.finalize()
		message = {'type': 'secure_x',
					'payload': base64.b64encode(cryptogram).decode('utf-8'),
					'salt': base64.b64encode(self._salt).decode('utf-8'),
					'mac': base64.b64encode(self.make_mac(key, cryptogram)).decode('utf-8'),
					'tag': ''
					}
		if self._mode == 'GCM':
			message['tag'] = base64.b64encode(encryptor.tag).decode('utf-8')
		return message

	def decrypt_message(self, encrypted_message, salt, mac, tag):
		encrypted_message = base64.b64decode(encrypted_message.encode('utf-8'))
		self._salt = base64.b64decode(salt.encode('utf-8'))
		mac = base64.b64decode(mac.encode('utf-8'))
		tag = base64.b64decode(tag.encode('utf-8'))
		cipher, key = self.make_cipher(tag)
		success = self.verify_mac(key, encrypted_message, mac)
		if not success:
			return False, 'Invalid Signature!'
		decryptor = cipher.decryptor()
		message = decryptor.update(encrypted_message) + decryptor.finalize()
		p = message[-1]
		if len(message) < p:
			return False, 'Invalid padding. Larger than message!'
		if not 0 < p <= cipher.algorithm.block_size / 8:
			return False, 'Invalid padding. Large than block size!'
		for x in message[-p:-1]:
			if x != p:
				return False, 'Invalid padding value!'
		return True, eval(message[:-p])

	def make_mac(self, key, message):
		h = hmac.HMAC(key, hashes.SHA256(), backend=backend)
		h.update(message)
		return h.finalize()

	def verify_mac(self, key, message, mac):
		h = hmac.HMAC(key, hashes.SHA256(), backend=backend)
		h.update(message)
		try:
			h.verify(mac)
			return True
		except InvalidSignature:
			return False


def get_all_combinations():
	control = ['SHA3-512', 'SHA3-384', 'SHA3-224', 'SHA3-256', 'SHA512-256', 'SHA512-224', 'SHA512', 'SHA384', 'SHA256', 'SHA224']
	algorithm = ['AES', '3DES', 'Camellia', 'CAST5', 'SEED', 'Blowfish', 'IDEA']
	mode = ['CBC', 'GCM', 'OFB', 'CFB', 'CFB8', 'CTR', 'ECB', 'XTS']
	key_exchange = ['DH', 'X25519', 'X448']
	combinations = []
	for k in key_exchange:
		for a in algorithm:
			if a == 'AES':
				length = [256, 192, 128]
			elif a == '3DES':
				length = [192, 128, 64]
			elif a == 'Camellia':
				length = [256, 192, 128]
			elif a == 'CAST5':
				length = [128, 64]
			elif a == 'SEED':
				length = [128]
			elif a == 'Blowfish':
				length = [448, 256, 192, 128, 64, 32]
			# elif a == 'IDEA':
			else:
				length = [128]
			for m in mode:
				if m == 'XTS':
					if a == 'AES':
						length = [256]
						for l in length:
							for c in control:
								combinations += [k+'_'+a+'_'+str(l)+'_'+m+'_'+c]
				else:
					if m == 'CTR':
						length = [x for x in length if x >= 128]
					for l in length:
						for c in control:
							combinations += [k + '_' + a + '_' + str(l) + '_' + m + '_' + c]
	return combinations
