import argparse
import asyncio
import base64
import json
import os

import coloredlogs
import logging

from cipher import MyCipher, get_all_combinations

logger = logging.getLogger('root')

STATE_CONNECT = 0
STATE_OPEN = 1
STATE_DATA = 2
STATE_CLOSE = 3


class ClientProtocol(asyncio.Protocol):
	"""
	Client that handles a single client
	"""
	def __init__(self, file_name, loop):
		"""
		Default constructor
		:param file_name: Name of the file to send
		:param loop: Asyncio Loop to use
		"""
		self.file_name = file_name
		self.loop = loop
		self.state = STATE_CONNECT  # Initial State
		self.buffer = ''  # Buffer to receive data chunks
		self.transport = None
		self.combination = get_all_combinations()
		self._try = 0
		self.count_data = 0
		self.cipher = None

	def connection_made(self, transport) -> None:
		"""
		Called when the client connects.
		:param transport: The transport stream to use for this client
		:return: No return
		"""
		self.transport = transport
		logger.debug('Connected to Server!')
		self._send({'type': 'cipher', 'data': self.combination[self._try]})
		logger.info("Send Cipher!")

	def data_received(self, data: str) -> None:
		"""
		Called when data is received from the server.
		Stores the data in the buffer
		:param data: The data that was received. This may not be a complete JSON message
		:return:
		"""
		logger.debug('Received: {}'.format(data))
		try:
			self.buffer += data.decode()
		except:
			logger.exception('Could not decode data from client')

		idx = self.buffer.find('\r\n')

		while idx >= 0:  # While there are separators
			frame = self.buffer[:idx + 2].strip()  # Extract the JSON object
			self.buffer = self.buffer[idx + 2:]  # Removes the JSON object from the buffer

			self.on_frame(frame)  # Process the frame
			idx = self.buffer.find('\r\n')

		if len(self.buffer) > 4096 * 1024 * 1024:  # If buffer is larger than 4M
			logger.warning('Buffer to large')
			self.buffer = ''
			self.transport.close()

	def on_frame(self, frame: str) -> None:
		"""
		Processes a frame (JSON Object)
		:param frame: The JSON Object to process
		:return:
		"""

		# logger.debug("Frame: {}".format(frame))
		try:
			message = json.loads(frame)
		except:
			logger.exception("Could not decode the JSON message!")
			self.transport.close()
			return

		mtype = message.get('type', None).upper()

		if mtype == 'CIPHER':
			self.process_cipher(message)
			return
		elif mtype == 'PUBLIC_KEY':
			self.process_public_key(message)
			return
		elif mtype == 'SECURE_X':
			success, decrypt_message = self.cipher.decrypt_message(message['payload'], message['salt'], 
					message['mac'], message['tag'])
			if success:
				mtype = decrypt_message.get('type', None).upper()
				if mtype == 'OK':
					if self.state == STATE_OPEN:
						logger.info("Channel open!")
						self.send_file(self.file_name)
					else:
						logger.warning("Ignoring message from server!")
					return
				elif mtype == 'PUBLIC_KEY':
					self.process_public_key(decrypt_message)
					return
			else:
				logger.info(decrypt_message)
		elif mtype == 'ERROR':
			logger.warning("Got error from server: {}!".format(message.get('data', None)))
		else:
			logger.warning("Invalid message type!")

		self.transport.close()
		self.loop.stop()

	def connection_lost(self, exc):
		"""
		Connection was lost for some reason.
		:param exc:
		:return:
		"""
		logger.info('The server closed the connection!')
		self.loop.stop()

	def send_file(self, file_name: str) -> None:
		"""
		Sends a file to the server.
		The file is read in chunks, encoded to Base64 and sent as part of a DATA JSON message
		:param file_name: File to send
		:return:  None
		"""
		self.state = STATE_DATA
		with open(file_name, 'rb') as f:
			message = {'type': 'DATA', 'data': None}
			read_size = 16 * 60
			close = False
			count = 0
			while True:
				data = f.read(16 * 60)
				if count >= self.count_data * 9:
					message['data'] = base64.b64encode(data).decode()
					encrypted_message = self.cipher.encrypt_message(message)
					self._send(encrypted_message)
					logger.info('Send File!')
					if len(data) != read_size:
						close = True
						break
					if (self.count_data + 1) * 9 == count:
						self.count_data += 1
						logger.info('Need new key!')
						self.send_public_key()
						break
				count += 1

			if close:
				self._send(self.cipher.encrypt_message({'type': 'CLOSE'}))
				logger.info("File transferred. Closing transport!")
				self.transport.close()

	def process_cipher(self, message) -> None:
		if message['data'] == 'ACCEPT':
			combination = self.combination[self._try].split('_')
			key_exchange = combination[0]
			cipher_algorithm = combination[1]
			length = combination[2]
			mode = combination[3]
			control = combination[4]
			self.cipher = MyCipher(key_exchange, cipher_algorithm, mode, control, length)
			self.send_public_key()
		elif message['data'] == 'REFUSE':
			self._try += 1
			if self._try == len(self.combination):
				self.transport.close()
				self.loop.stop()
			else:
				self._send({'type': 'cipher', 'data': self.combination[self._try]})
				logger.info("Send Cipher!")

	def send_public_key(self):
		self.cipher.make_keys()
		message = {'type': 'public_key', 'data': self.cipher.public_key()}
		if self.state == STATE_DATA:
			message = self.cipher.encrypt_message(message)
		self._send(message)
		logger.info("Send public key!")

	def process_public_key(self, message) -> None:
		self.cipher.key(message['data'])
		if self.state == STATE_CONNECT:
			self._send(self.cipher.encrypt_message({'type': 'OPEN', 'file_name': self.file_name}))
			logger.info("Send file name!")
			self.state = STATE_OPEN
		elif self.state == STATE_DATA:
			self.send_file(self.file_name)

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
	parser = argparse.ArgumentParser(description='Sends files to servers.')
	parser.add_argument('-v', action='count', dest='verbose',
						help='Shows debug messages',
						default=0)
	parser.add_argument('-s', type=str, nargs=1, dest='server', default='127.0.0.1',
						help='Server address (default=127.0.0.1)')
	parser.add_argument('-p', type=int, nargs=1,
						dest='port', default=5000,
						help='Server port (default=5000)')

	parser.add_argument(type=str, dest='file_name', help='File to send')

	args = parser.parse_args()
	file_name = os.path.abspath(args.file_name)
	level = logging.DEBUG if args.verbose > 0 else logging.INFO
	port = args.port
	server = args.server

	coloredlogs.install(level)
	logger.setLevel(level)

	logger.info("Sending file: {} to {}:{} LogLevel: {}".format(file_name, server, port, level))

	loop = asyncio.get_event_loop()
	coro = loop.create_connection(lambda: ClientProtocol(file_name, loop), server, port)
	loop.run_until_complete(coro)
	loop.run_forever()
	loop.close()


if __name__ == '__main__':
	main()
