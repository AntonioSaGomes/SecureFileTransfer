#!/usr/bin/env python
# -*- coding: utf-8 -*-

from cryptography.hazmat.primitives.ciphers.base import _CipherContext
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes,padding,serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import asymmetric
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.fernet import Fernet
import os,PyKCS11,sys
from cryptography.x509 import *
from cryptography.x509.oid import *
import json

backend = default_backend()

pkcs11 = PyKCS11.PyKCS11Lib()
pkcs11.load('C\\Windows\\System32\\pteidpkcs11.dl' if sys.platform == 'win32' else '/usr/local/lib/libpteidpkcs11.so')

class Cript():
	"""
	Stores the the different methods for the
	cryptography encryption/decryption process.
	- algo   -> Bulk encryption algorithms
	- mode   -> Mode of operation for symmetric-key
	- digest -> Hash function
	"""
	def __init__(self,algo,mode,digest):
		self.algo = algo
		self.mode = mode
		self.digest = digest

	def toJson(self):
		return json.dumps(self.__dict__)

class CitizenCard():
	
	def __init(self):
		self.name = None
		self.slot = pkcs11.getSlotList()[0]
		self.session = pkcs11.openSession(self.slot)
	
	def get_name():
		if self.name is None:
			certificate, *_ = self.get_x509_certificates()
			self.name = certificate.subject.get_attributes_for_oid(NameOID.COMON_NAME)[0].value
		return self.name
	
	def get_certificates(self):
		certificates = list()
		attribute_keys = [key for key in list(PyKCS11.CKA.keys()) if isinstance(key,int) ] 
		for obj in self.session.findObjects():
			attributes = self.session.getAttributeValue(obj,attribute_keys)
			attributes = dict(zip(map(PyKCS11.CKA.get, attribute_keys), attributes))
			if attributes['CKA_CERTIFICATE_TYPE'] != None:
				certificates.append(bytes(attributes['CKA_VALUE']))
		return certificates
		
	
	def get_x509_certificates(self,backend = backend, **kwargs):
		certificates = [ load_der_x509_certificate(certificate,backend) for certificate in self.get_certificates() ]
		
		for key,value in kwargs.items():
			if key in dir(ExtensionOID):
				certificates = [ certificate for certificate in certificates if value(certificate.extensions.get_extension_for_oid(getattr(ExtensionOID, key))) ] 
			elif key in dir(NameOID):
				certificates = [ certificate for certificate in certificates if value(certificate.subject.get_attributes_for_oid(getattr(NameOID, key))) ] 
		
		return certificates
	
	def get_x509_certification_chains(self, backend = backend, **kwargs):
		certificates = [ load_der_x509_certificate(certificate,backend)  for certificate in self.get_certificates() ]
		selected = list(certificates)
		if 'KEY_USAGE' not in  kwargs:
			kwargs['KEY_USAGE'] = lambda ku: ku.value.digital_signature and ku.value.key_agreement
		for key,value in kwargs.items():
			if key in dir(ExtensionOID):
				selected = [ certificate for certificate in selected if value(certificate.extensions.get_extension_for_oid(getattr(ExtensionOID, key))) ] 
			elif key in dir(NameOID):
				selected = [ certificate for certificate in selected if value(certificate.subject.get_attributes_for_oid(getattr(NameOID, key))) ] 
		return [ build_certification_chain(certificate, certificates) for certificate in selected ] 
		
		
		
	def get_public_key(self, transformation = lambda key: serialization.load_der_public_key(bytes(key.to_dict()['CKA_VALUE'])), backend=backend):
		return transformation(self.session.findObjects([
			(PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),
			 (PyKCS11.CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')
			])[0])
	
	def get_private_key(self):
		return self.session.findObjects([
			(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
			(PyKCS11.CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')
		])[0]
		
	def sign(self, content, mechanism = PyKCS11.CKM_SHA1_RSA_PKCS,param= None):
		return self.session.sign(self.get_private_key(),content, PyKCS11.Mechanism(mechanism, param)), mechanism, param
		
	def verify(key, signature, content, padder = asymmetric.padding.PKCS1v15(), hash = hashes.SHA1(), backend = backend):
		if type(key) == str:
			with open(key,'rb') as fin:
				key = deserialize(fin.read(), load_pem_x509_certificate)
		if type(key) == bytes:
			key = serialization.load_der_public_key(key, backend= backend)
		if type(key) == _Certificate:
			key = key.public_key()
		try:
			key.verify(signature,content,padder,hash)
		except cryptography.exceptions.InvalidSignature:
			return False
		return True
		
		
def load_cert(path, loader = load_pem_x509_certificate, backend = backend):
	if os.path.isfile(path):
		with open(path,'rb') as fin:
			content = fin.read()
			if loader == load_pem_x509_certificate:
				certificates = list()
				separator = b'-----END CERTIFICATE-----'
				length_separator = len(separator)
				while len(content) > 0:
					index = content.find(separator) + length_separator
					if index < len(content):
						certificates.append(loader(content[:index], backend))
						content = content[index:]
					else:
						break
				return certificates
			else:
				return [ loader(content,backend)]
	return []		
	
	
def build_certification_chain(certificates, trusted_certificates):
	if type(trusted_certificates) == list:
		trusted_certificates = { certificate.subject : certificate for certificate in trusted_certificates } 
	if type(trusted_certificates) == dict:
		certification_chain = list(certificates) if type(certificates) == list else [certificates]
		certificate = certification_chain[-1]
		if certificate.issuer not in trusted_certificates:
			return []
		while certificate.issuer != certificate.subject and certificate.issuer in trusted_certificates:
			certificate = trusted_certificates[certificate.issuer]
			certification_chain.append(certificate)
		return certification_chain
	return []

def gen_parameters(generator=2,key_size=2048,backend=backend):
	"""
	Generates some parameters for the DH key exchange process
	Note that in a DH handshake both peers must agree on a common
	set of parameters
	"""
	return dh.generate_parameters(generator,key_size,backend)


def get_asymm_keys(parameters):
	"""
	Generates and returns private key that will be used
	in the DH exchange process
	"""
	private_key = parameters.generate_private_key()
	return private_key,private_key.public_key()


def get_symetric_key():
	"""
	Returns a string of size random bits suitable for cryptographic use
	In this case the size=32
	"""
	return os.urandom(32)


def gen_Fernet_key():
	"""
	Generates and returns a fresh Fernet key that must be kept in
	a safe place!
	"""
	key = Fernet.generate_key()
	return key


def store_Fernet_key(key,filename):
	"""
	Creates or overrides a file with the fernet key passed as argument
	"""
	fich = open(str(filename) + '.key', 'wb')
	fich.write(key) # The key is type bytes still
	fich.close()


def load_Fernet_key(filename):
	"""
	Loads and returns the Fernet key present in the file passed as argument
	"""
	fich = open(str(filename) +'.key', 'rb')
	key = fich.read() # The key will be type bytes
	fich.close()
	return key


def fernet_encript(key,message):
	"""
	Takes the Fernet key and the message to be encrypted and
	returns the encrypted result
	"""
	f = Fernet(key)
	return f.encrypt(message)


def fernet_decript(key,message):
	"""
	Takes the Fernet key and the message to be decrypted and
	returns the decrypted result
	"""
	f = Fernet(key)
	return f.decrypt(message)


def encryptor(iv = os.urandom(16), key = os.urandom(32), bc = backend,key_type = 'AES128',mode='CBC'):
	"""
	Creates and returns a cipher encryptor based on the methods passed as argument
	Raises error if algorithm or mode is not supported
	(!) Careful were. Why pass iv and key as args. if we return them without doing nothing?
	"""
	if key_type == 'AES128':
		algo = algorithms.AES(key)
	elif key_type == 'ChaCha20':
		algo = algorithms.ChaCha20(key,nonce=os.urandom(32))
	else:
		raise('Error algorithm ' + key_type + ' not supported!')
	if mode == 'CBC':
		mode = modes.CBC(iv)
	elif mode == 'GCM':
		mode = modes.GCM(iv)
	else :
		raise('Error mode ' + mode + ' not supported!')
	cipher = Cipher(algo,mode,backend = bc)
	return iv,key,cipher.encryptor()


def store_private_key(private_key,filename):
	"""
	Open a PEM file and writes the private key in it
	"""
	with open(str(filename) + "_key.pem", "wb") as key_file:
		pem = private_key.private_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PrivateFormat.TraditionalOpenSSL,
		encryption_algorithm=serialization.NoEncryption()
	)
		key_file.write(pem)



def load_private_key(filename):
	"""
	Loads and returns the private key from the PEM file
	"""
	with open(str(filename) + "_key.pem", "rb") as key_file:
		return serialization.load_pem_private_key(
		key_file.read(),
		password=None,
		backend=default_backend()
	)


def encrypt(encryptor, data, algorithm = asymmetric.padding.OAEP, hashing = hashes.SHA256, mgf = asymmetric.padding.MGF1, label = None):

	if hashing == 'SHA256':
		hashing = hashes.SHA256()
	elif hashing == 'SHA512':
		hashing = hashes.SHA512()

	"""
	Takes the data and encrypt it with the help of the algorithm,
	the hash and a mask generation function
	"""
	if type(encryptor) == _CipherContext:
		padder = padding.PKCS7(128).padder()
		encrypted, data = data[:16], data[16:]
		encrypted = encryptor.update(encrypted if len(encrypted) == 16 else padder.update(encrypted) + padder.finalize())
		while len(data) != 0:
			concatenate, data = data[:16], data[16:]
			encrypted += encryptor.update(concatenate if len(concatenate) == 16 else padder.update(concatenate) + padder.finalize())
		return encrypted + encryptor.finalize()
	else:
		return encryptor.encrypt(data, algorithm(mgf = mgf(algorithm = hashing()), algorithm = hashing(), label = label)), algorithm, hashing, mgf, label

def decryptor(iv = os.urandom(16), key = os.urandom(32), bc = backend):
	"""
	Creates and returns a cipher to decrypt the data based on AES and the mode CBC
	"""
	cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend = bc)
	return iv, key, cipher.decryptor()


def generate_raiz():
	"""
	Generates a new root value for the OTP authentication process
	"""
	return os.urandom(12)


def otp(index=None,root=None,password=None,data=None):
	cont = 0
	if data != None:
		return hash(data=data)
	data = (password + str(root)).encode("utf8")
	while cont != index -1:
		result = hash(data=data)
		data = result
		cont+=1
	return data
	
	
def serializePrivateKey(private_key):
	"""
	Takes a private key and returns a serialized version of it
	The encoding type is PEM
	"""
	return private_key.private_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PrivateFormat.PKCS8,
		encryption_algorithm=serialization.NoEncryption()
	)


def serializePublicKey(public_key):
	"""
	Takes a public key and returns a serialized version of it
	The encoding type is PEM
	"""
	return public_key.public_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PublicFormat.SubjectPublicKeyInfo
	)


def challenge() :
	"""
		Create CHAP for client
		(Challenge handshake authentication protocol)
	""" 
	return [random.randint(1,9) for i in range(5)]



	
def solve_challenge():
	"""
		Solves the CHAP challenge
	"""
	return (challenge[0]*challenge[1]-challenge[2]) * challenge[3] - challenge[4]
	
		
def create_challenge():
	"""
	Used for the server to create a challenge for the client to solve
	"""
	return "oiasjfoajsfasfamcpm"
	
		
def solvePasswordChallenge(password,challenge,nonce):
	"""
	Used to solve the password-based authentication challenge
	Takes a password know by booth the server and client and nonce value 
	that is sent over the channel as part of the challenge
	"""
	print ("password: " + password)
	print ("challenge: " + challenge)
	print ("nonce: " + str(nonce))

	data = (password  + challenge + str(nonce)).encode("utf8")
	print (hash(data= data))
	return hash(data= data)
	
def verifyPasswordChallenge(password,challenge,nonce,solution):
	"""
	Server verifies if the challenge was solved 
	correctly by the client.
	It solves the challenge and compares the client solution
	with its own.
	"""
	print ("password: " + password)
	print ("challenge: " + challenge)
	print ("nonce: " + str(nonce))
	
	
	data = (password  + challenge + str(nonce)).encode("utf8")
	print (hash(data= data))
	print (solution)
	return hash(data= data) == solution
	
	

def serializeParameters(parameters):
	"""
	Takes some parameters and returns a serialized version of those
	The encoding type is PEM
	"""
	return parameters.parameter_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.ParameterFormat.PKCS3
	)


def deserializePrivateKey(string, bc = backend):
	"""
	Takes a string (private key), loading it performing a deserialize operation
	The encoding type was PEM
	"""
	if type(string) == str:
		string = string.encode('utf8')
	return serialization.load_pem_private_key(string, password = None , backend = bc)


def deserializePublicKey(string, bc = backend):
	"""
	Takes a string (public key), loading it performing a deserialize operation
	The encoding type was PEM
	"""
	if type(string) == str:
		string = string.encode('utf8')
	return serialization.load_pem_public_key(string , backend = bc)


def deserializeParameters(string, bc = backend):
	"""
	Takes a string (some parameters), loading those performing a deserialize operation
	The encoding type was PEM
	"""
	if type(string) == str:
		string = string.encode('utf8')
	return serialization.load_pem_parameters(string , backend = bc)


def shared_key(private_key,public_key):
	"""
	Returns a shared key that comes from the private and public key (DH)
	"""
	return private_key.exchange(public_key)


def encrypt_message(message,public_key,symetric_key):
	"""
	Encrypts a message using a Advance Encryption Standard (AES) key
	used with the Counter with CBC-MAC (CCM) mode of operation
	"""
	if message != None:
		nonce = os.urandom(12)
		message = AESCCM(symetric_key).encrypt(nonce,message.encode("iso-8859-1"),None)
		nonce, *_ = encrypt(public_key,nonce)
		message ={'nonce' : nonce.decode("iso-8859-1"),'message':message.decode("iso-8859-1")}

	return message


def get_rsa_asymn_keys(public_exponent = 65537, key_size = 2048, bc = backend):
	"""
	Generates and returns new RSA private and public keys
	"""
	private_key = asymmetric.rsa.generate_private_key(public_exponent = public_exponent, key_size = key_size, backend = bc)
	return private_key,private_key.public_key()


def decrypt_message(data,symetric_key,private_key):
	"""
	Decrypts a message previously encrypted using the encrypt_message function
	Needs a private_key to do it
	"""
	if type(data) == str or type(data) == bytes:
		data = json.loads(data)
	typ = data['type']
	nonce = data['nonce'].encode("iso-8859-1")
	message = data['message'].encode("iso-8859-1")
	nonce, *_ = decrypt(private_key,nonce)
	message = AESCCM(symetric_key).decrypt(nonce,message,None)
	message ={'type':typ,'nonce' : nonce.decode("iso-8859-1"),'message':message.decode("iso-8859-1")}
	return message


def derive_key(shared_key,algorithm):
	"""
	Takes the shared_key from DH Shared Key, derives it using
	the SHA256 or SHA512 Hash function and then returns the result
	"""
	if algorithm == 'SHA256':
		algorithm = hashes.SHA256()
	if algorithm == 'SHA512':
		algorithm = hashes.SHA512()
	derived_key = HKDF(
				algorithm = algorithm,
				length = 32,
				salt = None,
				info=b'handshake data',
				backend = backend
			).derive(shared_key)
	return derived_key


def decrypt(decryptor, data, algorithm = asymmetric.padding.OAEP, hashing = hashes.SHA256, mgf = asymmetric.padding.MGF1, label = None):
	if hashing == 'SHA256':
		hashing = hashes.SHA256()
	elif hashing == 'SHA512':
		hashing = hashes.SHA512()
	"""
	Takes the data and decrypt it with the help of the algorithm,
	the hash and a mask generation function
	Does the 'reverse' thing of the encrypt function
	"""
	if type(decryptor) == _CipherContext:
		data = decryptor.update(data) + decryptor.finalize()
		unpadder = padding.PKCS7(128).unpadder()
		try:
			return unpadder.update(data) + unpadder.finalize()
		except:
			return data
	else:
		return decryptor.decrypt(data, algorithm(mgf = mgf(algorithm = hashing()), algorithm = hashing(), label = label)), algorithm, hashing, mgf, label


def hash(data, size = 512, algorithm = hashes.SHA512(), backend = backend):
	"""
	Very well known hash function - SHA - in the cryptographic world
	Default is SHA512 but SHA256 is also available
	"""
	digest = hashes.Hash(algorithm, backend)
	todigest, remaining = data[:size], data[size:]
	digest.update(todigest)
	while len(remaining) > 0:
		todigest, remaining = remaining[:size], remaining[size:]
		digest.update(todigest)
	return digest.finalize()

