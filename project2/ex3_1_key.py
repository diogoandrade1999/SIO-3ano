import os
from getpass import getpass
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64

backend = default_backend()

def derive_key(password):
	salt = os.urandom(16)
	kdf = PBKDF2HMAC(
		algorithm=hashes.SHA256(),
		length=32,
		salt=salt,
		iterations=100000,
		backend=backend
	)

	key = kdf.derive(password.encode('utf-8'))
	return salt, key

def sym_encript(key, algo_name, text):
	if algo_name == 'AES':
		algo = algorithms.AES(key)
	elif algo_name =='3DWS':
		algo = algorithms.TriplesDWS(key)
	elif algo_name =='ChaCha20':
		algo = algorithms.ChaCha20(key)
	else:
		raise(Exception('Invalid algo'))
		
	bs = int(algo.block_size / 8)
	missing_bytes = bs - len(text) % bs
	if missing_bytes == 0:
		missing_bytes = bs
	padding = bytes([missing_bytes] * missing_bytes)
	text += padding
	print('Padding: {}: {}:'.format(missing_bytes, padding))
	print('Text + Padding ({}): {}'.format(len(padding), text))
	
	cipher = Cipher(algo, modes.ECB(), backend=backend)
	encryptor = cipher.encryptor()
	cryptogram = encryptor.update(text) + encryptor.finalize()
	return cryptogram

def sym_decript(key, algo_name, cryptogram):
	if algo_name == 'AES':
		algo = algorithms.AES(key)
	elif algo_name =='3DWS':
		algo = algorithms.TriplesDWS(key)
	elif algo_name =='ChaCha20':
		algo = algorithms.ChaCha20(key)
	else:
		raise(Exception('Invalid algo'))
		
	cipher = Cipher(algo, modes.ECB(), backend=backend)
	decryptor = cipher.decryptor()
	text = decryptor.update(cryptogram) + decryptor.finalize()
	
	p = text[-1]
	if len(text) < p:
		raise( Exception('Invalid padding. Larger than text'))
	if not 0 < p <= algo.block_size / 8:
		raise(Exception('Invalid padding. Large than block size'))
	
	for x in text[-p:-1]:
		if x != p:
			raise(Exception('Invalid padding value.'))
	return text[:-p]
	
password = getpass('Password: ')
salt, key = derive_key(password)
print('Password: {}\nSalt: {}\nkey: {}'.format(password, base64.b64encode(salt), base64.b64encode(key)))
text = input("Text: ").encode('utf-8')
cryptogram = sym_encript(key, 'AES', text)
print('Cryptogram: {}'.format(base64.b64encode(cryptogram)))
text_d = sym_decript(key, 'AES', cryptogram)
print('Original Text: {}\nDecriptd Text: {}\nSame: {}'.format(text.decode(), text_d.decode(), text == text_d))
