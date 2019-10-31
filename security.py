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
import os 
import json

backend = default_backend()



class Cript():
	
	def __init__(self,algo,mode,digest):
		self.algo = algo
		self.mode = mode
		self.digest = digest
	
	def toJson(self):
		return json.dumps(self.__dict__)

def gen_parameters(generator=2,key_size=2048,backend=backend):
		return dh.generate_parameters(generator,key_size,backend)

def get_asymm_keys(parameters):
	private_key = parameters.generate_private_key()
	return private_key,private_key.public_key()
	
def get_symetric_key():
	return os.urandom(32)
def encryptor(iv = os.urandom(16), key = os.urandom(32), bc = backend,key_type = 'AES128',mode='CBC'):
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
	with open(str(filename) + "_key.pem", "wb") as key_file:
		pem = private_key.private_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PrivateFormat.TraditionalOpenSSL,
		encryption_algorithm=serialization.NoEncryption()
	)
		key_file.write(pem)


	
def store_public_key():
	pass

def load_private_key(filename):
	with open(str(filename) + "_key.pem", "rb") as key_file:
		return serialization.load_pem_private_key(
		key_file.read(),
		password=None,
		backend=default_backend()
	)

	
def encrypt(encryptor, data, algorithm = asymmetric.padding.OAEP, hashing = hashes.SHA256, mgf = asymmetric.padding.MGF1, label = None):
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
	cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend = bc)
	return iv, key, cipher.decryptor()

def serializePrivateKey(private_key):
	return private_key.private_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PrivateFormat.PKCS8,
		encryption_algorithm=serialization.NoEncryption()
	)

def serializePublicKey(public_key):
	return public_key.public_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PublicFormat.SubjectPublicKeyInfo
	)
			
def serializeParameters(parameters):
	return parameters.parameter_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.ParameterFormat.PKCS3
	)

def deserializePrivateKey(string, bc = backend):
	if type(string) == str:
		string = string.encode('utf8')
	return serialization.load_pem_private_key(string, password = None , backend = bc)

def deserializePublicKey(string, bc = backend):
	if type(string) == str:
		string = string.encode('utf8')
	return serialization.load_pem_public_key(string , backend = bc)
	
def deserializeParameters(string, bc = backend):
	if type(string) == str:
		string = string.encode('utf8')
	return serialization.load_pem_parameters(string , backend = bc)
	
def shared_key(private_key,public_key):
	return private_key.exchange(public_key)
	

def encrypt_message(message,public_key,symetric_key):
	if message != None:	
		nonce = os.urandom(12)
		print (nonce)
		print (symetric_key)
		message = AESCCM(symetric_key).encrypt(nonce,message.encode("iso-8859-1"),None)
		nonce, *_ = encrypt(public_key,nonce)
		message ={'nonce' : nonce.decode("iso-8859-1"),'message':message.decode("iso-8859-1")}
	
	return message

def get_rsa_asymn_keys(public_exponent = 65537, key_size = 2048, bc = backend):
	private_key = asymmetric.rsa.generate_private_key(public_exponent = public_exponent, key_size = key_size, backend = bc)
	return private_key,private_key.public_key()
	
def decrypt_message(data,symetric_key,private_key):
	if type(data) == str or type(data) == bytes:
		data = json.loads(data)
	typ = data['type']
	nonce = data['nonce'].encode("iso-8859-1")
	message = data['message'].encode("iso-8859-1")
	nonce, *_ = decrypt(private_key,nonce)
	print (nonce)
	print(symetric_key)
	message = AESCCM(symetric_key).decrypt(nonce,message,None)
	message ={'type':typ,'nonce' : nonce.decode("iso-8859-1"),'message':message.decode("iso-8859-1")}
	return message
	
	
	
def derive_key(shared_key,algorithm):
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
	digest = hashes.Hash(algorithm, backend)
	todigest, remaining = data[:size], data[size:]
	digest.update(todigest)
	while len(remaining) > 0:
		todigest, remaining = remaining[:size], remaining[size:]
		digest.update(todigest)
	return digest.finalize()


