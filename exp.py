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


pkcs11 = PyKCS11.PyKCS11Lib()
pkcs11.load('C\\Windows\\System32\\pteidpkcs11.dl' if sys.platform == 'win32' else '/usr/local/lib/libpteidpkcs11.so')

backend = default_backend()

class CitizenCard():
	
	def __init__(self):
		self.name = None
		self.slot = pkcs11.getSlotList()[0]
		self.session = pkcs11.openSession(self.slot)
	
	def get_name(self):
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
		
backend = default_backend()

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
			print("here")
			return []
		while certificate.issuer != certificate.subject and certificate.issuer in trusted_certificates:
			print (certificate)
			certificate = trusted_certificates[certificate.issuer]
			certification_chain.append(certificate)
		return certification_chain
	return []


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

raiz = os.urandom(12)

a = otp(4,raiz,"hello")

b = otp(3,raiz,"hello")

c = otp(data=b)

cert = load_cert('client_cert.pem')

trusted_certificates =  load_cert('PTEID.pem') + load_cert('client_cert.pem') + load_cert('server_cert.pem')

trusted_certificates = { certificate.subject : certificate for certificate in trusted_certificates } 

b = build_certification_chain(cert,trusted_certificates)


cit = CitizenCard()

content = "hello"

a = cit.get_name()

signature = cit.sign("hello")

boll = cit.verify(cit.get_public_key(),signature,content)

print (boll)




