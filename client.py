import asyncio
import json
import base64
import argparse
import coloredlogs, logging
import os
import security 
from security import Cript
logger = logging.getLogger('root')

STATE_CONNECT = 0
STATE_OPEN = 1
STATE_DATA = 2
STATE_CLOSE = 3


class ClientProtocol(asyncio.Protocol):
	"""
	Client that handles a single client
	"""

	def __init__(self, file_name, loop,cript):
		"""
		Default constructor
		:param file_name: Name of the file to send
		:param loop: Asyncio Loop to use
		"""

		self.file_name = file_name
		self.loop = loop
		self.state = STATE_CONNECT  # Initial State
		self.buffer = ''  # Buffer to receive data chunks
		self.cript = Cript('AES128','CBC','SHA256')

	def connection_made(self, transport) -> None:
		"""
		Called when the client connects.

		:param transport: The transport stream to use for this client
		:return: No return
		"""
		self.transport = transport

		logger.debug('Connected to Server')
		
		
		cript = self.cript.toJson()
		
		self.parameters = security.gen_parameters()
		
		self.private_key,self.public_key = security.get_asymm_keys(self.parameters)
		
		self.rsa_private_key,self.rsa_public_key = security.get_rsa_asymn_keys()
		

		public_key = security.serializePublicKey(self.public_key).decode("utf8")
		
		rsa_public_key = security.serializePublicKey(self.rsa_public_key).decode("utf8")
		
		parameters = security.serializeParameters(self.parameters).decode("utf8")
		
		
		message = {'type': 'OPEN', 'file_name': self.file_name, 'cript': cript,'client_public_key':public_key,'client_rsa_public_key':rsa_public_key,'parameters':parameters}
		
		self._send(message)

		self.state = STATE_OPEN

	def negotiation(self,transport) -> None:
		"""
		Called when the client connects
		
		Negotiate the algorithms used
		:param transport: The transport stream to use for this client
		:return: No return
		"""
		self.transport = transport
		logger.debug('Negotiating terms')
		
		
		message = {'type': 'NEGOTIATION', 'cript':self.cript}
		self._send(message)
		
		self.state = STATE_OPEN
		
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

		#logger.debug("Frame: {}".format(frame))
		try:
			message = json.loads(frame)
		except:
			logger.exception("Could not decode the JSON message")
			self.transport.close()
			return

		mtype = message.get('type', None)
		
		#message used for choosing the algorithms used in the session
		if mtype == 'ALGORITHMS':		
			message = {'type':'ALGORITHMS','message': 'Choose the algorithms you would like to be used for the encryption'}
			self._send(message)
			self.state = STATE_OPEN
			
		#message used for rsa and dh keys exchange
		if mtype == 'EXCHANGE':			
			
			self.parameters = security.gen_parameters()
		
			self.private_key,self.public_key = security.get_asymm_keys(self.parameters)
			
			self.rsa_private_key,self.rsa_public_key = security.get_rsa_asymn_keys()
			

			public_key = security.serializePublicKey(self.public_key).decode("utf8")
			
			rsa_public_key = security.serializePublicKey(self.rsa_public_key).decode("utf8")
			
			parameters = security.serializeParameters(self.parameters).decode("utf8")
		
			message = {'type': 'OPEN', 'file_name': self.file_name, 'cript': cript,'client_public_key':public_key,'client_rsa_public_key':rsa_public_key,'parameters':parameters}
		
			self._send(message)

			self.state = STATE_OPEN
		
		if mtype == 'NEGOTIATION':
			pass
		if mtype == 'OK':  # Server replied OK. We can advance the state
			if self.state == STATE_OPEN:
				logger.info("Channel open")						
				server_public_key = message['server_public_key']
				server_rsa_public_key = message['server_rsa_public_key']
				
				iv_enc = message['iv_enc'].encode("iso-8859-1")
				sym_key_enc = message['sym_key_enc'].encode("iso-8859-1")
				
				iv = security.decrypt(self.rsa_private_key,iv_enc)[0]
				self.sym_key = security.decrypt(self.rsa_private_key,sym_key_enc)[0]
				
				iv,key,self.decryptor = security.decryptor(iv=iv,key=self.sym_key)
				
				
				self.server_rsa_public_key = security.deserializePublicKey(server_rsa_public_key)
				self.server_public_key = security.deserializePublicKey(server_public_key)
				
				self.send_file(self.file_name)
			elif self.state == STATE_DATA:  # Got an OK during a message transfer.
				# Reserved for future use
				pass
			else:
				logger.warning("Ignoring message from server")
			return

		elif mtype == 'ERROR':
			logger.warning("Got error from server: {}".format(message.get('data', None)))
		else:
			logger.warning("Invalid message type")

		self.transport.close()
		self.loop.stop()

	def connection_lost(self, exc):
		"""
		Connection was lost for some reason.
		:param exc:
		:return:
		"""
		logger.info('The server closed the connection')
		self.loop.stop()

	def send_file(self, file_name: str) -> None:
		"""
		Sends a file to the server.
		The file is read in chunks, encoded to Base64 and sent as part of a DATA JSON message
		:param file_name: File to send
		:return:  None
		"""

		#shared key used for encryption
		
		shared_key = security.shared_key(self.private_key,self.server_public_key)

		self.shared_key = security.derive_key(shared_key,self.cript.digest)
		
		
		iv,key,encryptor = security.encryptor(key = self.shared_key)
		
		
		
		
		with open(file_name, 'rb') as f:
			message = {'type': 'DATA', 'data': None,'iv': None}
			read_size = 16 * 60
			while True:
				data = f.read(16 * 60)
				data = security.encrypt(encryptor,data= data)
				message['data'] = base64.b64encode(data).decode()
				message['iv'] = base64.b64encode(iv).decode()
				message_type = dict(list(message.items())[:1])
				message_data = dict(list(message.items())[1:])
				message_data = security.encrypt_message(str(message_data),self.server_rsa_public_key,self.sym_key)
				message = {**message_type,**message_data}
				self._send(message)

				if len(data) != read_size:
					break
					
			self._send({'type': 'CLOSE'})
			logger.info("File transferred. Closing transport")
			self.transport.close()

	def _send(self, message: str) -> None:
		"""
		Effectively encodes and sends a message
		:param message:
		:return:
		"""
		logger.debug("Send: {}".format(message))

		#need to encrypt message
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
	parser.add_argument('-c',type=str, nargs=1,dest='cipher', default='AES128')
	parser.add_argument('-d',type=str, nargs=1,dest='digest', default='SHA256')
	parser.add_argument('-m',type=str, nargs=1,dest='mode', default='CBC')
						

	parser.add_argument(type=str, dest='file_name', help='File to send')

	args = parser.parse_args()
	file_name = os.path.abspath(args.file_name)
	level = logging.DEBUG if args.verbose > 0 else logging.INFO
	port = args.port
	server = args.server
	
	cript = Cript(args.cipher,args.mode,args.cipher)
	

	coloredlogs.install(level)
	logger.setLevel(level)

	logger.info("Sending file: {} to {}:{} LogLevel: {}".format(file_name, server, port, level))

	loop = asyncio.get_event_loop()
	coro = loop.create_connection(lambda: ClientProtocol(file_name, loop,cript),
								  server, port)
	loop.run_until_complete(coro)
	loop.run_forever()
	loop.close()

if __name__ == '__main__':
	main()
