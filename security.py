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
import os 
import json

backend = default_backend()

class Cript():
	'''
	Cript class
	Stores the the different methods for the 
	cryptography encryption/decryption process.
	- algo   -> Bulk encryption algorithms
	- mode   -> Mode of operation for symmetric-key
	- digest -> Hash function
	'''
	def __init__(self,algo,mode,digest):
		self.algo = algo
		self.mode = mode
		self.digest = digest
	
	def toJson(self):
		return json.dumps(self.__dict__)


def gen_parameters(generator=2,key_size=2048,backend=backend):
	  '''
		gen_parameters function
		Generates some parameters for the DH key exchange process
		Note that in a DH handshake both peers must agree on a common
		set of parameters
	  '''
		return dh.generate_parameters(generator,key_size,backend)


def get_asymm_keys(parameters):
	'''
	get_asymm_keys function
	Generates and returns private key that will be used 
	in the DH exchange process
	'''
	private_key = parameters.generate_private_key()
	return private_key,private_key.public_key()
	

def get_symetric_key():
	'''
	get_symetric_key function
	Returns a string of size random bits suitable for cryptographic use
	In this case the size=32
	'''
	return os.urandom(32)


def gen_Fernet_key():
	'''
	gen_Fernet_key function
	Generates and returns a fresh Fernet key that must be kept in
	a safe place!
	'''
	key = Fernet.generate_key()
	return key
	

def store_Fernet_key(key,filename):
	'''
	store_Fernet_key function
	Creates or overrides a file with the fernet key passed as argument
	'''
	fich = open(str(filename) + '.key', 'wb')
	fich.write(key) # The key is type bytes still
	fich.close()


def load_Fernet_key(filename):
	'''
	load_Fernet_key
	Loads and returns the Fernet key present in the file passed as argument
	'''
	fich = open(str(filename) +'.key', 'rb')
	key = fich.read() # The key will be type bytes
	fich.close()
	return key
	

def fernet_encript(key,message):
	'''
	fernet_encript function
	Takes the Fernet key and the message to be encrypted and 
	returns the encrypted result
	'''
	f = Fernet(key)
	return f.encrypt(message)


def fernet_decript(key,message):
	'''
	fernet_decript function
	Takes the Fernet key and the message to be decrypted and
	returns the decrypted result
	'''
	f = Fernet(key)
	return f.decrypt(message)

	
def encryptor(iv = os.urandom(16), key = os.urandom(32), bc = backend,key_type = 'AES128',mode='CBC'):
	'''
	encryptor function
	Creates and returns a cipher encryptor based on the methods passed as argument
	(!) Careful were. Why pass iv and key as args. if we return them without doing nothing?
	'''
	if (key_type == 'AES128'):
		algo = algorithms.AES(key)
	elif (key_type == 'ChaCha20'):
		algo = algorithms.ChaCha20(key,nonce=os.urandom(32))
	else:
		raise('Error algorithm ' + key_type + ' not supported!')
	if (mode == 'CBC'):
		mode = modes.CBC(iv)
	elif (mode == 'GCM'): 
		mode = modes.GCM(iv)
	else :
		raise('Error mode ' + mode + ' not supported!')
	cipher = Cipher(algo,mode,backend = bc)
	return iv,key,cipher.encryptor()


def store_private_key(private_key,filename):
	'''
	store_private_key function
	Open a PEM file and writes the private key in it
	'''
	with open(str(filename) + "_key.pem", "wb") as key_file:
		pem = private_key.private_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PrivateFormat.TraditionalOpenSSL,
		encryption_algorithm=serialization.NoEncryption()
	)
		key_file.write(pem)


def store_public_key():
	'''
	store_public_key function
	(!)
	'''
	pass


def load_private_key(filename):
	'''
	load_private_key function
	Loads and returns the private key from the PEM file
	'''
	with open(str(filename) + "_key.pem", "rb") as key_file:
		return serialization.load_pem_private_key(
		key_file.read(),
		password=None,
		backend=default_backend()
	)

	
def encrypt(encryptor, data, algorithm = asymmetric.padding.OAEP, hashing = hashes.SHA256, mgf = asymmetric.padding.MGF1, label = None):
  '''
	encrypt function
	
	'''
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
	'''
	decrypt function
	
	(!) Careful were. Why pass iv and key as args. if we return them without doing nothing?
	'''
	cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend = bc)
	return iv, key, cipher.decryptor()


def serializePrivateKey(private_key):
	'''
	serializePrivateKey function
	
	'''
	return private_key.private_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PrivateFormat.PKCS8,
		encryption_algorithm=serialization.NoEncryption()
	)


def serializePublicKey(public_key):
	'''
	serializePublicKey function
	
	'''
	return public_key.public_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PublicFormat.SubjectPublicKeyInfo
	)

			
def serializeParameters(parameters):
	'''
	serializeParameters function
	
	'''
	return parameters.parameter_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.ParameterFormat.PKCS3
	)


def deserializePrivateKey(string, bc = backend):
	'''
	deserializePrivateKey function
	
	'''
	if type(string) == str:
		string = string.encode('utf8')
	return serialization.load_pem_private_key(string, password = None , backend = bc)


def deserializePublicKey(string, bc = backend):
	'''
	deserializePublicKey function
	
	'''
	if type(string) == str:
		string = string.encode('utf8')
	return serialization.load_pem_public_key(string , backend = bc)

	
def deserializeParameters(string, bc = backend):
	'''
	deserializeParameters function
	
	'''
	if type(string) == str:
		string = string.encode('utf8')
	return serialization.load_pem_parameters(string , backend = bc)

	
def shared_key(private_key,public_key):
	'''
	shared_key function
	
	'''
	return private_key.exchange(public_key)
	

def encrypt_message(message,public_key,symetric_key):
	'''
	encrypt_message function
	
	'''
	if message != None:	
		nonce = os.urandom(12)
		message = AESCCM(symetric_key).encrypt(nonce,message.encode("iso-8859-1"),None)
		nonce, *_ = encrypt(public_key,nonce)
		message ={'nonce' : nonce.decode("iso-8859-1"),'message':message.decode("iso-8859-1")}
	
	return message


def get_rsa_asymn_keys(public_exponent = 65537, key_size = 2048, bc = backend):
	'''
	get_rsa_asymn_keys function
	
	'''
	private_key = asymmetric.rsa.generate_private_key(public_exponent = public_exponent, key_size = key_size, backend = bc)
	return private_key,private_key.public_key()

	
def decrypt_message(data,symetric_key,private_key):
	'''
	decrypt_message function
	
	'''
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
	'''
	derive_key function
	
	'''
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
	'''
	decrypt function
	
	'''
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
	'''
	hash function
	
	'''
	digest = hashes.Hash(algorithm, backend)
	todigest, remaining = data[:size], data[size:]
	digest.update(todigest)
	while len(remaining) > 0:
		todigest, remaining = remaining[:size], remaining[size:]
		digest.update(todigest)
	return digest.finalize()

