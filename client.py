import asyncio
import json
import base64
import argparse
import coloredlogs, logging
import os
import security 
from security import Cript
import pickle
logger = logging.getLogger('root')

STATE_CONNECT = 0
STATE_OPEN = 1
STATE_DATA = 2
STATE_CLOSE = 3
STATE_NEGOTIATION = 4
STATE_EXCHANGE = 5
STATE_CHAP = 6
STATE_AUTH_PASS = 7
STATE_AUTH_CARD = 8
STATE_AUTH_OTP = 9
STATE_CLIENT_ACCESS_CONTROL = 10
STATE_SERVER_ACCESS_CONTROL = 11
STATE_CLIENT_RSA_AUTH = 12
STATE_SERVER_RSA_AUTH = 13

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
		self.fernet_filename = "fernet_key"
		self.password = "hello"
		self.citizen_card = security.CitizenCard()
		self.cert_fingerprints = [ b"K\xbb\xe2\xb0kl\xf8[\x1c\xbdjM\x1f\xcaVh\xc4\x8a\xeb\x02u+\x99}\x82!\xc3\xe3\x8f\xb5\xa4'"]


	def connection_made(self, transport) -> None:
		"""
		Called when the client connects.

		:param transport: The transport stream to use for this client
		:return: No return
		"""
		self.transport = transport
		
		self.fernet_key = security.load_Fernet_key(self.fernet_filename)

		logger.debug('Connected to Server')
		
		
		message = {'type': 'OPEN', 'file_name': self.file_name}
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

		data = security.fernet_decript(self.fernet_key,data)

		
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

		mtype = message['type']

		
		if mtype == 'RSA_EXCHANGE':		
			self.send_dh_exchange(message)
			
			
		elif mtype == 'DH_EXCHANGE':	
			self.send_assymetric_key_authentication(message)		
			#self.send_citizen_card_auth(message)
		
		elif mtype == 'CHAP':
			self.send_challenge_solution(message)	
		
		elif mtype == 'OTP_AUTH':
			self.send_otp_solution(message)
		
		elif mtype == 'SERVER_ACCESS_CONTROL':
			ret = self.process_server_access_control(message)
		
		elif mtype == 'SERVER_CERT_AUTH':
			ret = self.process_x509_server_authentication(message)
			
		elif mtype == 'SERVER_RSA_AUTH':
			ret = self.process_server_asym_key_authentication(message)
			if ret:
				self.send_file(self.file_name)

		elif mtype == 'CITIZEN_CARD_AUTH':
			self.send_citizen_card_auth()
			
		elif mtype == 'OK':  # Server replied OK. We can advance the state
			if self.state == STATE_OPEN:
				self.send_client_acess_control()
				#self.send_negotiation()
			elif self.state == STATE_DATA:  # Got an OK during a message transfer.
				# Reserved for future use
				pass
			elif self.state == STATE_NEGOTIATION:
				self.send_exchange(message)
			elif self.state == STATE_CHAP:
				self.send_start_otp_auth()	
			elif self.state == STATE_AUTH_PASS:
				pass
			elif self.state == STATE_CLIENT_ACCESS_CONTROL:
				self.start_server_access_control()
			elif self.state == STATE_AUTH_CARD:
				self._send({"type":"CHAP"})
			elif self.state == STATE_AUTH_OTP:
				self.send_negotiation()
			else:
				logger.warning("Ignoring message from server")
			return

		elif mtype == 'ERROR':
			logger.warning("Got error from server: {}".format(message.get('data', None)))
		else:
			print(mtype)
			logger.warning("Invalid message type: {}".format(message['type']))

		#self.transport.close()
		#self.loop.stop()


	def connection_lost(self, exc):
		"""
		Connection was lost for some reason.
		:param exc:
		:return:
		"""
		logger.info('The server closed the connection')
		self.loop.stop()


	def start_server_access_control(self) -> None:
		
		message = {"type": "SERVER_ACCESS_CONTROL"}
		
		self._send(message)

	def send_client_acess_control(self):
		
		"""
		Client sends a challenge to check if the server can access client.
		Sends a challenge with the client's CC id number and a nonce value
		"""
		
		serial_number = self.citizen_card.get_id_number()
		
		nonce = os.urandom(12).decode('iso-8859-1')
		
		challenge = security.challenge_serial_number(serial_number,nonce)
		
		message = {"type": "CLIENT_ACCESS_CONTROL", 'challenge':challenge.decode('iso-8859-1'),'nonce':nonce}
		
		self._send(message)
		
		self.state = STATE_CLIENT_ACCESS_CONTROL
	
	
	def process_server_access_control(self,message) -> bool:
		
		"""
			Client verifies if the server can access the client
			Checks if the the digest sent by the server is 
			a product of the hash of server cert fingerprint
		"""
			
		self.state = STATE_SERVER_ACCESS_CONTROL
		
		digest = message['digest']
		
		if security.verify_hashes(digest,self.cert_fingerprints) != True:

			return False
		
		message = {'type':'OK'}
		
		self._send(message)
		
		return True
		
		
		
	def send_start_authentication(self) -> None:
		
		message = {'type':'AUTH'}
		
		self._send(message)
	
	
	def send_start_otp_auth(self) -> None:
		
		message = {'type':'OTP_AUTH'}
		self._send(message)
	
		
	def send_challenge_solution(self,message: str) -> None:
		"""
		Send client CHAP challenge authentication 
		solution to the server
		"""
		challenge = message['challenge'].encode('iso-8859-1')
		nonce = os.urandom(12).decode("iso-8859-1")			
		solution = security.solvePasswordChallenge(self.password,challenge,nonce)
		solution = security.encrypt(self.server_pub_key,solution)[0]
		message = {'type':'CHAP','nonce':nonce,'solution':solution.decode("iso-8859-1")}
		self._send(message)
		self.state = STATE_CHAP
	
					
	def send_otp_solution(self,message: str) -> None:
		"""
		Send client otp authentication solution
		to the server
		"""
		raiz = message['raiz'] 	
		indice = message['indice']
		solution = security.otp(index= indice-1,root= raiz, password=self.password).decode('iso-8859-1')
		solution = security.encrypt(self.server_pub_key,solution)[0]
		message = {'type':'OTP_AUTH', 'solution':solution.decode("iso-8859-1") }
		self._send(message)
		self.state = STATE_AUTH_OTP
				
		
	
	
	def send_citizen_card_auth(self) -> None:	
		#read Citizen card
		self.citizen_card = security.CitizenCard()
		security.store_public_key(self.citizen_card.get_public_key(),"client")
		#content to be signed
		content = os.urandom(12)
		#sign content private key from citizenCard
		self.signature = self.citizen_card.sign(content)[0]
		signature = bytes(self.signature)
		#need to send certificate chain
		chain = self.citizen_card.get_x509_certification_chains()[0]		
		certificates = [security.serialize(certificate).decode('iso-8859-1') for certificate in chain]	
		message = {'type': 'CITIZEN_CARD_AUTH', 'signature': signature.decode('iso-8859-1'), 'content':content.decode('iso-8859-1'), 'certificates':certificates}	
		self._send(message)	
		self.state = STATE_AUTH_CARD
	
	
	def process_x509_server_authentication(self,message: str) -> bool:
		#server cert priv_key signature
		signature = bytes(message['signature'], encoding='iso-8859-1')
		#content that was signed by server cert priv_key
		content = message['content'].encode('iso-8859-1')
		#server certificate
		certificate = message['server_cert'].encode('iso-8859-1')		
		certificate = security.deserialize(certificate, security.load_pem_x509_certificate) 		
		self.server_pub_key = certificate.public_key()
		#load trusted_certificates
		trusted_certificates =  security.load_cert('PTEID.pem') + security.load_cert('ca.pem') 
		#build certification chain
		chain = security.build_certification_chain(certificate,trusted_certificates)
		#verify certification chain 
		if security.valid_certification_chain(chain,[{
			'KEY_USAGE': lambda ku: ku.value.digital_signature and ku.value.key_agreement
		}] + [{
			'KEY_USAGE': lambda ku: ku.value.key_cert_sign and ku.value.crl_sign
		}] * 3, check_revogation = [ True ] * 3 + [ False ]) != True:
			return False
			
		#verify signature 
		if security.verify(certificate,signature,content) != True:
			return False
		
		message = {'type': 'OK'}
				
		self._send(message)
		
		return True
		
	def send_negotiation(self) -> None:
		"""
		Called when the client connects
		
		Negotiate the algorithms used
		:param transport: The transport stream to use for this client
		:return: No return
		"""
		logger.debug('Negotiating terms')
		
		hashing_algo = None
		cipher_mode = None
		cipher = None
		
		while hashing_algo not in [1,2]:
			hashing_algo = int(input("Hashing algorithm \n 1)SHA256 \n 2)SHA512\n"))
			if hashing_algo == 1:
				self.cript.digest = "SHA256"
			else : 
				self.cript.digest = "SHA512"
			
		while cipher_mode not in [1,2]:
			cipher_mode = int(input("Cipher mode \n 1)CBC \n 2)GCM\n"))
			if cipher_mode == 1:
				self.cript.mode = "CBC"
			else : 
				self.cript.mode = "GCM"
		while cipher not in [1,2]:
			cipher = int(input("Cipher \n 1)AES128 \n 2)CHACHA20\n"))
			if cipher == 1:
				self.cript.algo = "AES128"
			else : 
				self.cript.algo = "CHACHA20"
	
		cript = self.cript.toJson()
		message = {'type':'NEGOTIATION','cript':cript}
		self._send(message)
		
		self.state = STATE_NEGOTIATION
		
		
	def send_exchange(self,message: str) -> None:
		"""
		Called when rsa_keys  need to be exchanged

		:param data: The data that was received. This may not be a complete JSON message
		:return:
		"""
		
		self.rsa_private_key,self.rsa_public_key = security.get_rsa_asymn_keys()			
			
		rsa_public_key = security.serializePublicKey(self.rsa_public_key).decode("utf8")
			
		message = {'type': 'RSA_EXCHANGE', 'client_rsa_public_key':rsa_public_key}
		
		self._send(message)

		self.state = STATE_EXCHANGE
				
	def send_dh_exchange(self,message: str) -> None:
		
		server_rsa_public_key = message['server_rsa_public_key']

		self.server_rsa_public_key = security.deserializePublicKey(server_rsa_public_key)
					
		iv_enc = message['iv_enc'].encode("iso-8859-1")
		
		sym_key_enc = message['sym_key_enc'].encode("iso-8859-1")
		
		iv = security.decrypt(self.rsa_private_key,iv_enc)[0]
		
		self.sym_key = security.decrypt(self.rsa_private_key,sym_key_enc)[0]
		
		iv,key,self.decryptor = security.decryptor(iv=iv,key=self.sym_key)
		
		iv,key,self.encryptor = security.encryptor(iv=iv,key=self.sym_key)
		
		self.parameters = security.gen_parameters()
		
		self.dh_private_key,self.dh_public_key = security.get_asymm_keys(self.parameters)
			
		dh_public_key = security.serializePublicKey(self.dh_public_key).decode("utf8")
		
		parameters = security.serializeParameters(self.parameters).decode("utf8")
						
		message = {'type': 'DH_EXCHANGE', 'client_dh_public_key':dh_public_key,'enc_parameters':parameters}
		
		self._send(message)


	def send_assymetric_key_authentication(self,message: str) -> None:
		
		"""
		Client sends a request to the client to authenticate
		Using the clients rsa public key it encrypts the value
		Finnaly it hashes the original nonce value for authentication
		""" 
		server_dh_public_key = message['server_dh_public_key']
		
		self.server_dh_public_key = security.deserializePublicKey(server_dh_public_key)
		
		nonce = os.urandom(12)
		
		enc_nonce = security.encrypt(self.server_rsa_public_key,nonce)[0]
		
		digest = security.hash(nonce)
		
		message = {'type': 'CLIENT_RSA_AUTH','nonce':enc_nonce.decode('iso-8859-1'),'digest':digest.decode('iso-8859-1')}
		
		self._send(message)
		
		self.state = STATE_CLIENT_RSA_AUTH
		
	
	def process_server_asym_key_authentication(self,message: str) -> bool:
		
		"""
		Client receives an auth request
		Using its private asym key decrypts the nonce 
		Generates the hash with decrypted nonce and compares with digest received.
		"""
		
		server_digest = message['digest'].encode('iso-8859-1')
		
		enc_nonce = message['nonce'].encode('iso-8859-1')
		
		nonce = security.decrypt(self.rsa_private_key,enc_nonce)[0]
		
		digest = security.hash(nonce)
		
		if server_digest != digest : 
			return False
		
		return True
		
		
		
				
	def send_file(self,file_name: str) -> None:
		"""
		Sends a file to the server.
		The file is read in chunks, encoded to Base64 and sent as part of a DATA JSON message
		:param file_name: File to send
		:return:  None
		"""
		
		#shared key used for encryption of the file content
		
		shared_key = security.shared_key(self.dh_private_key,self.server_dh_public_key)
	
		self.shared_key = security.derive_key(shared_key,self.cript.digest)
		
		iv,key,encryptor = security.encryptor(key = self.shared_key)
		
		
		
		
		with open(file_name, 'rb') as f:
			message = {'type': 'DATA', 'data': None,'iv': None}
			read_size = 16 * 60
			while True:
				data = f.read(16 * 60)
				#encrypt with encryptor with the derived shared key
				data = security.encrypt(encryptor,data= data,hashing=self.cript.digest)
				#encrypt with encryptor with symmetric key
				data = security.encrypt(self.encryptor,data=data,hashing=self.cript.digest)
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

		#need to encrypt message
		message_b = (json.dumps(message) + '\r\n').encode()
		message_b = security.fernet_encript(self.fernet_key,message_b)
		
		logger.debug("Send: {}".format(message_b))

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
