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
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.fernet import Fernet
import os,PyKCS11,sys
import cryptography
import datetime
import urllib
from cryptography import x509
from cryptography.x509 import *
from cryptography.x509.oid import *
from cryptography.hazmat.backends.openssl.x509 import _Certificate
import json
import urllib.request
import inspect
import security

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
			self.name = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
		return self.name
		
	def get_id_number(self):
		certificate, *_ = self.get_x509_certificates()
		self.id_number = certificate.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)[0].value
		return self.id_number 
		
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
	
	def get_public_key_cert(self):
		return self.session.findObjects([
					(PyKCS11.CKA_CLASS,1),
					(PyKCS11.CKA_LABEL,'CITIZEN AUTHENTICATION CERTIFICATE')
				])[0]
				
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
		
		
		
	def get_public_key(self, transformation = lambda key: serialization.load_der_public_key(bytes(key.to_dict()['CKA_VALUE']), backend=backend)):
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
	
	

	
def load_crls(certificate, backend = backend):
	try:
		crlDistributionPoints = certificate.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
		crlDistributionPoints = crlDistributionPoints.value
		crlDistributionPoints = [ obj.value for crlDistributionPoints in crlDistributionPoints for obj in crlDistributionPoints.full_name if type(obj) == x509.general_name.UniformResourceIdentifier ] 
		return [ load_der_x509_crl(urllib.request.urlopen(crlDistributionPoint).read(), backend) for crlDistributionPoint in crlDistributionPoints ]
	except ExtensionNotFound:
		return []
		
def not_expired(certificate):
	now = datetime.datetime.now()
	return now >= certificate.not_valid_before and now <= certificate.not_valid_after

def regovation_status(certificate, backend= backend):
	return int(any([ certificate.serial_number in [ rc.serial_number for rc in crl ] for crl in load_crls(certificate, backend) ] ))
	

def valid_certification_chain(certification_chain, vkwargs, backend = backend, check_revogation = None):
	if check_revogation is None:
		check_revogation = [ True ] * len(certification_chain)
	if not all([ (not to_revokate or regovation_status(certificate,backend) == 0) and not_expired(certificate) and valid_attributes(certificate, kwargs) for certificate, kwargs, to_revokate in zip(certification_chain, vkwargs, check_revogation) ] ):
		return False
	for i in range(len(certification_chain) - 1):
		try:
			certificate0, certificate1 = certification_chain[i], certification_chain[i + 1]
			certificate1.public_key().verify(certificate0.signature, certificate0.tbs_certificate_bytes, asymmetric.padding.PKCS1v15(), certificate0.signature_hash_algorithm)
		except cryptography.exceptions.InvalidSignature:
			return False
	if certification_chain[-1].subject == certification_chain[-1].issuer:
		try:
			certificate0, certificate1 = certification_chain[-1],certification_chain[-1]
			certificate1.public_key().verify(certificate0.signature, certificate0.tbs_certificate_bytes, asymmetric.padding.PKCS1v15(), certificate0.signature_hash_algorithm)
		except cryptography.exceptions.InvalidSignature:
			return False
	return True


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


def build_certification_chain(certificates, trusted_certificates):
	if type(trusted_certificates) == list:
		trusted_certificates = { certificate.subject : certificate for certificate in trusted_certificates }
	if type(trusted_certificates) == dict:
		certification_chain = list(certificates) if type(certificates) == list else [ certificates ]
		certificate = certification_chain[-1]
		if certificate.issuer not in trusted_certificates:
			return [ ]
		while certificate.issuer != certificate.subject and certificate.issuer in trusted_certificates:
			certificate = trusted_certificates[certificate.issuer]
			certification_chain.append(certificate)
		return certification_chain
	return [ ]

def valid_attributes(certificate, kwargs):
	for key, value in kwargs.items():
		if key in dir(ExtensionOID):
			obj = certificate.extensions.get_extension_for_oid(getattr(ExtensionOID, key))
			print (obj)
		elif key in dir(NameOID):
			print("got here also for some reason")
			obj = certificate.extensions.get_extension_for_oid(getattr(NameOID, key))
		else:
			print("here")
			continue
		if not value(obj):
			print ("not valid_attributes")
			return False
	return True


cit = security.CitizenCard()

priv_key = cit.get_private_key()

print(dir(priv_key))
"""
fingerprints = [b'\xc2O\xc8~\x9dc\x1c\xde6b\xbbYD?\x92\xd2\xf3\xdev\xbe\xb8\xb5h\x8e"jfY\xf0\x9fJ%']	

server_cert = security.load_cert('server_cert.pem')[0]

rsa_priv_key,rsa_pub_key = security.get_asymm_keys()


server_pub_key = server_cert.public_key()
		
print (server_cert)

trusted_certificates =   load_cert('PTEID.pem') + load_cert('ca.pem') 

certification_chain = build_certification_chain(server_cert,trusted_certificates)


valid = security.valid_certification_chain(certification_chain, [{
			'KEY_USAGE': lambda ku: ku.value.digital_signature and ku.value.key_agreement
		}] + [{
			'KEY_USAGE': lambda ku: ku.value.key_cert_sign and ku.value.crl_sign
		}] * 3, check_revogation = [ True ] * 3 + [ False ])
		
print ("valid certificate chain? : " + str(valid))


client_cert = cit.get_x509_certificates()[0]

"""
#cert = security.loadPrivateKey('server_privkey')


"""

trusted_certificates =   load_cert('PTEID.pem') + load_cert('ca.pem') 

	
trusted_certificates = { certificate.subject : certificate for certificate in trusted_certificates }


certification_chain = build_certification_chain(cert,trusted_certificates)




valid = security.valid_certification_chain(certification_chain, [{
			'KEY_USAGE': lambda ku: ku.value.digital_signature and ku.value.key_agreement
		}] + [{
			'KEY_USAGE': lambda ku: ku.value.key_cert_sign and ku.value.crl_sign
		}] * 3, check_revogation = [ True ] * 3 + [ False ])
		
print ("valid certificate chain? : " + str(valid))

"""


"""

raiz = os.urandom(12)

a = otp(4,raiz,"hello")

b = otp(3,raiz,"hello")

c = otp(data=b)

   



def store_public_key(pub_key,filename):
	#Open a PEM file and writes the public key in it
	
	with open(str(filename) + '_pub_key.pem','wb') as fin:
		pem = pub_key.public_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PublicFormat.SubjectPublicKeyInfo
		)
		fin.write(pem)



pub_key = cit.get_public_key()

print(type(pub_key))

	
#print(valid_attributes(load_cert('client_cert.pem')[0],{
 #       'KEY_USAGE': lambda ku: ku.value.digital_signature and ku.value.key_agreement }))

def hash_fingerprint(cert):
	digest = hash(cert.fingerprint(hashes.SHA256())).decode('iso-8859-1')
	return digest

def verify_hashes(digesto,fingerprints):
	digests = [ hash(digest) for digest in fingerprints ]
	if digesto not in digests:
		return True
	return False
	
def asdsad(fname):
	with open(fname,'rb') as fin:
		data = fin.read()
		cert = x509.load_pem_x509_certificate(data,default_backend())
	return cert

client_cert = cit.get_x509_certificates()

digest = hash_fingerprint(client_cert)





print (verify_hashes(digest,fingerprints))
	
"""

