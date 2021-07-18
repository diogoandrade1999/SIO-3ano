import argparse
import asyncio
import base64
import json
import os
import re

import coloredlogs
import logging
from aio_tcpserver import tcp_server

from cipher import MyCipher, get_all_combinations
from rsa import MyRSA
from certs import MyCerts
from cryptography.x509.oid import NameOID

logger = logging.getLogger('root')

STATE_CONNECT = 0
STATE_OPEN = 1
STATE_DATA = 2
STATE_CLOSE = 3

# GLOBAL
storage_dir = 'files'
valid_users = {'diogo': ['diogo', True], 'andre': ['andre', False]}
valid_ccs = {} # 'BI151840229': True, 'BI159151899': False}


class ClientHandler(asyncio.Protocol):
	def __init__(self, signal):
		"""
		Default constructor
		"""
		self.signal = signal
		self.state = 0
		self.file = None
		self.file_name = None
		self.file_path = None
		self.storage_dir = storage_dir
		self.buffer = ''
		self.peername = ''
		self.transport = None
		self.cipher = None
		self.combination = get_all_combinations()
		self.rsa = None
		self.certs = None
		self.permission = False

	def connection_made(self, transport) -> None:
		"""
		Called when a client connects

		:param transport: The transport stream to use with this client
		:return:
		"""
		self.peername = transport.get_extra_info('peername')
		logger.info('\n\nConnection from {}'.format(self.peername))
		self.transport = transport
		self.state = STATE_CONNECT

	def data_received(self, data: bytes) -> None:
		"""
		Called when data is received from the client.
		Stores the data in the buffer
		:param data: The data that was received. This may not be a complete JSON message
		:return:
		"""
		logger.debug('Received: {}'.format(data))
		try:
			self.buffer += data.decode()
		except:
			logger.exception('Could not decode data from client!')

		idx = self.buffer.find('\r\n')

		while idx >= 0:  # While there are separators
			frame = self.buffer[:idx + 2].strip()  # Extract the JSON object
			self.buffer = self.buffer[idx + 2:]  # Removes the JSON object from the buffer

			self.on_frame(frame)  # Process the frame
			idx = self.buffer.find('\r\n')

		if len(self.buffer) > 4096 * 1024 * 1024:  # If buffer is larger than 4M
			logger.warning('Buffer to large!')
			self.buffer = ''
			self.transport.close()

	def on_frame(self, frame: str) -> None:
		"""
		Called when a frame (JSON Object) is extracted
		:param frame: The JSON object to process
		:return:
		"""
		# logger.debug("Frame: {}".format(frame))

		try:
			message = json.loads(frame)
		except:
			logger.exception("Could not decode JSON message: {}".format(frame))
			self.transport.close()
			return

		mtype = message.get('type', "").upper()

		if mtype == 'CIPHER':
			ret = self.process_cipher(message)
		elif mtype == 'PUBLIC_KEY':
			ret = self.process_public_key(message)
		elif mtype == 'SECURE_X':
			success, decrypt_message = self.cipher.decrypt_message(message['payload'], message['salt'], 
					message['mac'], message['tag'])
			if success:
				mtype = decrypt_message.get('type', "").upper()
				if mtype == 'OPEN':
					if self.permission:
						ret = self.process_open(decrypt_message)
					else:
						logger.info("Don't have permissions!")
						self.state = STATE_CLOSE
						self.transport.close()
						ret = False
				elif mtype == 'DATA':
					ret = self.process_data(decrypt_message)
				elif mtype == 'CLOSE':
					ret = self.process_close(decrypt_message)
				elif mtype == 'PUBLIC_KEY':
					ret = self.process_public_key(decrypt_message)
				elif mtype == 'CHALLENGE':
					ret = self.process_challenge(decrypt_message)
				elif mtype == 'SIGNATURE':
					ret = self.process_siganture(decrypt_message)
				elif mtype == 'CA':
					ret = self.process_ca(decrypt_message)
				elif mtype == 'NONCE':
					ret = self.process_nonce(decrypt_message)
				else:
					logger.warning("Invalid message type: {}!".format(decrypt_message['type']))
					ret = False
			else:
				logger.warning("{}".format(decrypt_message))
				ret = False
		else:
			logger.warning("Invalid message type: {}!".format(message['type']))
			ret = False

		if not ret:
			try:
				self._send({'type': 'ERROR', 'message': 'See server'})
			except:
				pass # Silently ignore

			logger.info("Closing transport!")
			if self.file is not None:
				self.file.close()
				self.file = None

			self.state = STATE_CLOSE
			self.transport.close()

	def process_open(self, message: dict) -> bool:
		"""
		Processes an OPEN message from the client
		This message should contain the filename
		:param message: The message to process
		:return: Boolean indicating the success of the operation
		"""
		logger.debug("Process Open: {}".format(message))

		if self.state != STATE_CONNECT:
			logger.warning("Invalid state. Discarding!")
			return False

		if not 'file_name' in message:
			logger.warning("No filename in Open!")
			return False

		# Only chars and letters in the filename
		file_name = re.sub(r'[^\w\.]', '', message['file_name'])
		file_path = os.path.join(self.storage_dir, file_name)
		if not os.path.exists("files"):
			try:
				os.mkdir("files")
			except:
				logger.exception("Unable to create storage directory!")
				return False

		try:
			self.file = open(file_path, "wb")
			logger.info("File open!")
		except Exception:
			logger.exception("Unable to open file!")
			return False

		self._send(self.cipher.encrypt_message({'type': 'OK'}))

		self.file_name = file_name
		self.file_path = file_path
		self.state = STATE_OPEN
		return True

	def process_data(self, message: dict) -> bool:
		"""
		Processes a DATA message from the client
		This message should contain a chunk of the file
		:param message: The message to process
		:return: Boolean indicating the success of the operation
		"""
		logger.debug("Process Data: {}".format(message))

		if self.state == STATE_OPEN:
			self.state = STATE_DATA
			# First Packet

		elif self.state == STATE_DATA:
			# Next packets
			pass

		else:
			logger.warning("Invalid state. Discarding!")
			return False

		try:
			data = message.get('data', None)
			if data is None:
				logger.debug("Invalid message. No data found!")
				return False

			bdata = base64.b64decode(message['data'])
		except:
			logger.exception("Could not decode base64 content from message.data!")
			return False

		try:
			self.file.write(bdata)
			self.file.flush()
		except:
			logger.exception("Could not write to file!")
			return False

		return True

	def process_close(self, message: dict) -> bool:
		"""
		Processes a CLOSE message from the client.
		This message will trigger the termination of this session
		:param message: The message to process
		:return: Boolean indicating the success of the operation
		"""
		logger.debug("Process Close: {}".format(message))

		self.transport.close()
		if self.file is not None:
			self.file.close()
			self.file = None

		self.state = STATE_CLOSE
		logger.info("File transferred. Closing transport!")
		return True

	def process_cipher(self, message: dict) -> bool:
		logger.debug("Process Cipher: {}".format(message))
		if self.state == STATE_CONNECT:
			pass
		else:
			logger.warning("Invalid state. Discarding!")
			return False
		try:
			data = message.get('data', None)
			if data is None:
				logger.debug("Invalid message. No data found!")
				return False
			if message['data'] in self.combination:
				combination = message['data'].split('_')
				key_exchange = combination[0]
				cipher_algorithm = combination[1]
				length = combination[2]
				mode = combination[3]
				control = combination[4]
				self.cipher = MyCipher(key_exchange, cipher_algorithm, mode, control, length)
				self._send({'type': 'cipher', 'data': 'ACCEPT'})
				logger.info("Send accept combination!")
			else:
				self._send({'type': 'cipher', 'data': 'REFUSE'})
				logger.info("Send refuse combination!")
		except:
			logger.exception("Could not decode base64 content from message.data!")
			return False
		return True

	def process_public_key(self, message: dict) -> bool:
		logger.debug("Process Public Key: {}!".format(message))
		if self.state == STATE_CONNECT:
			pass
		elif self.state == STATE_DATA:
			pass
		else:
			logger.warning("Invalid state. Discarding!")
			return False
		try:
			data = message.get('data', None)
			if data is None:
				logger.debug("Invalid message. No data found!")
				return False
			self.cipher.make_keys()
			new_message = {'type': 'public_key', 'data': self.cipher.public_key()}
			if self.state == STATE_DATA:
				new_message = self.cipher.encrypt_message(new_message)
			self._send(new_message)
			self.cipher.key(message['data'])
			logger.info('Send public key!')
		except:
			logger.exception("Could not decode base64 content from message.data!")
			return False
		return True

	def process_challenge(self, message: dict) -> bool:
		logger.debug("Process challenge {}!".format(message))
		if self.state == STATE_CONNECT:
			pass
		else:
			logger.warning("Invalid state. Discarding!")
			return False
		try:
			data = message.get('data', None)
			if data is None:
				logger.debug("Invalid message. No data found!")
				return False
			self.certs = MyCerts(True)
			self.rsa = MyRSA()
			self.rsa.import_key(data)
			self._send(self.cipher.encrypt_message({'type': 'nonce', 'data': self.rsa.get_nonce()}))
			logger.info('Send nonce!')
		except:
			logger.exception("Could not decode base64 content from message.data!")
			return False
		return True

	def process_ca(self, message: dict) -> bool:
		logger.debug("Process CA {}!".format(message))
		if self.state == STATE_CONNECT:
			pass
		else:
			logger.warning("Invalid state. Discarding!")
			return False
		try:
			data = message.get('data', None)
			if data is None:
				logger.debug("Invalid message. No data found!")
				return False
			self.certs = MyCerts(True, True)
			self.certs.set_cert(data)
			valid, text = self.certs.get_issuers(self.certs.other_cert)
			if not valid:
				logger.info(text)
				self.state = STATE_CLOSE
				self.transport.close()
				return
			valid, text = self.certs.validation(text)
			if not valid:
				logger.info(text)
				self.state = STATE_CLOSE
				self.transport.close()
				logger.info('Invalid certificate!')
				return False
			self._send(self.cipher.encrypt_message({'type': 'nonce', 'data': self.certs.get_nonce()}))
			logger.info('Send nonce!')
		except:
			logger.exception("Could not decode base64 content from message.data!")
			return False
		return True

	def process_siganture(self, message: dict) -> bool:
		logger.debug("Process SIGNATURE {}!".format(message))
		if self.state == STATE_CONNECT:
			pass
		else:
			logger.warning("Invalid state. Discarding!")
			return False
		try:
			if 'username' in message:
				username = message.get('username', None)
			signature = message.get('signature', None)
			if ('username' in message and username is None) and signature is None:
				logger.debug("Invalid message. No data found!")
				return False
			if 'username' in message:
				if username not in valid_users:
					return False
				self.permission = valid_users[username][1]
				valid, text = self.rsa.verification(valid_users[username][0].encode(), signature)
			else:
				bi = self.certs.other_cert.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)[0].value
				if bi in valid_ccs:
					self.permission = valid_ccs[bi]
				valid, text = self.certs.verification(signature)
			if not valid:
				logger.info(text)
				self.state = STATE_CLOSE
				self.transport.close()
				return False
			self._send(self.cipher.encrypt_message({'type': 'CA', 'data': self.certs.get_cert()}))
			logger.info('Send ca!')
		except:
			logger.exception("Could not decode base64 content from message.data!")
			return False
		return True

	def process_nonce(self, message: dict) -> bool:
		logger.debug("Process nonce {}!".format(message))
		if self.state == STATE_CONNECT:
			pass
		else:
			logger.warning("Invalid state. Discarding!")
			return False
		try:
			data = message.get('data', None)
			if data is None:
				logger.debug("Invalid message. No data found!")
				return False
			self._send(self.cipher.encrypt_message({'type': 'SIGNATURE', 'signature': self.certs.sign(message['data'])}))
			logger.info('Send signature!')
		except:
			logger.exception("Could not decode base64 content from message.data!")
			return False
		return True

	def _send(self, message: dict) -> None:
		"""
		Effectively encodes and sends a message
		:param message:
		:return:
		"""
		logger.debug("Send: {}".format(message))

		message_b = (json.dumps(message) + '\r\n').encode()
		self.transport.write(message_b)


def main():
	global storage_dir

	parser = argparse.ArgumentParser(description='Receives files from clients.')
	parser.add_argument('-v', action='count', dest='verbose',
						help='Shows debug messages (default=False)',
						default=0)
	parser.add_argument('-p', type=int, nargs=1,
						dest='port', default=5000,
						help='TCP Port to use (default=5000)')

	parser.add_argument('-d', type=str, required=False, dest='storage_dir',
						default='files',
						help='Where to store files (default=./files)')

	parser.add_argument('-b', nargs='*',
						dest='bi', default=None,
						help='Identify user by cc')

	args = parser.parse_args()
	storage_dir = os.path.abspath(args.storage_dir)
	level = logging.DEBUG if args.verbose > 0 else logging.INFO
	port = args.port
	if port <= 0 or port > 65535:
		logger.error("Invalid port")
		return

	if port < 1024 and not os.geteuid() == 0:
		logger.error("Ports below 1024 require eUID=0 (root)")
		return

	if args.bi is not None:
		if len(args.bi) % 2 != 0:
			logger.error("Invalid number args BI!")
			return
		for x in range(0, len(args.bi), 2):
			n = args.bi[x]
			p = args.bi[x+1]
			if len(n) != 9:
				logger.error(f"Invalid BI number {n} (9 numbers)!")
				return
			if p not in ['True', 'False']:
				logger.error(f"Invalid BI permission {p} (True/False)!")
				return
			valid_ccs['BI'+n] = eval(args.bi[x+1])
	print(valid_ccs)

	coloredlogs.install(level)
	logger.setLevel(level)

	logger.info("Port: {} LogLevel: {} Storage: {}".format(port, level, storage_dir))
	tcp_server(ClientHandler, worker=2, port=port, reuse_port=True)


if __name__ == '__main__':
	main()


