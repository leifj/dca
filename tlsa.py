#!/usr/bin/python

# tlsa - A tool to create DANE/TLSA records. (called 'swede' before)
# This tool is really simple and not foolproof, it doesn't check the CN in the
# Subject field of the certificate. It also doesn't check if the supplied
# certificate is a CA certificate if usage 1 is specified (or any other
# checking for that matter).
#
# Usage is explained when running this program with --help
#
# This tool is loosly based on the 'dane' program in the sshfp package by Paul
# Wouters and Christopher Olah
#
# Copyright Pieter Lexis (pieter.lexis@os3.nl)
#
# License: GNU GENERAL PUBLIC LICENSE Version 2 or later

VERSION="2.5"

import sys
import os
import socket
import unbound
import re
from M2Crypto import X509, SSL
from binascii import a2b_hex, b2a_hex
from hashlib import sha256, sha512
from ipaddr import IPv4Address, IPv6Address

ROOTKEY="/etc/unbound/root.key"
DLVKEY="/etc/unbound/dlv.isc.org.key"
CAFILE='/etc/pki/tls/certs/ca-bundle.crt'

def genTLSA(hostname, protocol, port, certificate, output='generic', usage=1, selector=0, mtype=1):
	"""This function generates a TLSARecord object using the data passed in the parameters,
	it then validates the record and returns the RR as a string.
	"""
	# check if valid vars were passed
	if hostname[-1] != '.':
		hostname += '.'

	certificate = loadCert(certificate)
	if not certificate:
		raise Exception('Cannot load certificate from disk')

	# Create the record without a certificate
	if port == '*':
		record = TLSARecord(name='%s._%s.%s'%(port,protocol,hostname), usage=usage, selector=selector, mtype=mtype, cert ='')
	else:
		record = TLSARecord(name='_%s._%s.%s'%(port,protocol,hostname), usage=usage, selector=selector, mtype=mtype, cert ='')
	# Check if the record is valid
	if record.isValid:
		if record.selector == 0:
			# Hash the Full certificate
			record.cert = getHash(certificate, record.mtype)
		else:
			# Hash only the SubjectPublicKeyInfo
			record.cert = getHash(certificate.get_pubkey(), record.mtype)

	record.isValid(raiseException=True)

	if output == 'generic':
		return record.getRecord(generic=True)
	return record.getRecord()

def getA(hostname, secure=True):
	"""Gets a list of A records for hostname, returns a list of ARecords"""
	records = ""
	try:
		records = getRecords(hostname, rrtype='A', secure=secure)
	except InsecureLookupException, e:
		print str(e)
	except DNSLookupError, e:
		print 'Unable to resolve %s: %s' % (hostname, str(e))
	ret = []
	for record in records:
		ret.append(ARecord(hostname, str(IPv4Address(int(b2a_hex(record),16)))))
	return ret

def getAAAA(hostname, secure=True):
	"""Gets a list of A records for hostname, returns a list of AAAARecords"""
	records = ""
	try:
		records = getRecords(hostname, rrtype='AAAA', secure=secure)
	except InsecureLookupException, e:
		print str(e)
	except DNSLookupError, e:
		print 'Unable to resolve %s: %s' % (hostname, str(e))
	ret = []
	for record in records:
		ret.append(AAAARecord(hostname, str(IPv6Address(int(b2a_hex(record),16)))))
	return ret

def getVerificationErrorReason(num):
	"""This function returns the name of the X509 Error based on int(num)
	"""
	# These were taken from the M2Crypto.m2 code
	return {
50: "X509_V_ERR_APPLICATION_VERIFICATION",
22: "X509_V_ERR_CERT_CHAIN_TOO_LONG",
10: "X509_V_ERR_CERT_HAS_EXPIRED",
9:  "X509_V_ERR_CERT_NOT_YET_VALID",
28: "X509_V_ERR_CERT_REJECTED",
23: "X509_V_ERR_CERT_REVOKED",
7:  "X509_V_ERR_CERT_SIGNATURE_FAILURE",
27: "X509_V_ERR_CERT_UNTRUSTED",
12: "X509_V_ERR_CRL_HAS_EXPIRED",
11: "X509_V_ERR_CRL_NOT_YET_VALID",
8:  "X509_V_ERR_CRL_SIGNATURE_FAILURE",
18: "X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT",
14: "X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD",
13: "X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD",
15: "X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD",
16: "X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD",
24: "X509_V_ERR_INVALID_CA",
26: "X509_V_ERR_INVALID_PURPOSE",
17: "X509_V_ERR_OUT_OF_MEM",
25: "X509_V_ERR_PATH_LENGTH_EXCEEDED",
19: "X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN",
6:  "X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY",
4:  "X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE",
5:  "X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE",
3:  "X509_V_ERR_UNABLE_TO_GET_CRL",
2:  "X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT",
20: "X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
21: "X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE",
0:  "X509_V_OK"}[int(num)]

def getRecords(hostname, rrtype='A', secure=True):
	"""Do a lookup of a name and a rrtype, returns a list of binary coded strings. Only queries for rr_class IN."""
	ctx = unbound.ub_ctx()
	#ctx.add_ta_file(ROOTKEY)
	unbound.ub_ctx_trustedkeys(ctx,ROOTKEY)
	ctx.set_option("dlv-anchor-file:", DLVKEY)
	# Use the local cache
	ctx.resolvconf('/etc/resolv.conf')

	if type(rrtype) == str:
		if 'RR_TYPE_' + rrtype in dir(unbound):
			rrtype = getattr(unbound, 'RR_TYPE_' + rrtype)
		else:
			raise Exception('Error: unknown RR TYPE: %s.' % rrtype)
	elif type(rrtype) != int:
		raise Exception('Error: rrtype in wrong format, neither int nor str.')

	status, result = ctx.resolve(hostname, rrtype=rrtype)
	if status == 0 and result.havedata:
		if not result.secure:
			if secure:
				# The data is insecure and a secure lookup was requested
				raise InsecureLookupException('Error: query data not secure and secure data requested, unable to continue')
		# If we are here the data was either secure or insecure data is accepted
		return result.data.raw
	else:
		raise DNSLookupError('Unsuccesful lookup or no data returned for rrtype %s.' % rrtype)

def getHash(certificate, mtype):
	"""Hashes the certificate based on the mtype.
	The certificate should be an M2Crypto.X509.X509 object (or the result of the get_pubkey() function on said object)
	"""
	certificate = certificate.as_der()
	if mtype == 0:
		return b2a_hex(certificate)
	elif mtype == 1:
		return sha256(certificate).hexdigest()
	elif mtype == 2:
		return sha512(certificate).hexdigest()
	else:
		raise Exception('mtype should be 0,1,2')

def getTLSA(hostname, port=443, protocol='tcp', secure=True):
	"""
	This function tries to do a secure lookup of the TLSA record.
	At the moment it requests the TYPE52 record and parses it into a 'valid' TLSA record
	It returns a list of TLSARecord objects
	"""
	if hostname[-1] != '.':
		hostname += '.'

	if not protocol.lower() in ['tcp', 'udp', 'sctp']:
		raise Exception('Error: unknown protocol: %s. Should be one of tcp, udp or sctp' % protocol)
	try:
		if port == '*':
			records = getRecords('*._%s.%s' % (protocol.lower(), hostname), rrtype=52, secure=secure)
		else:
			records = getRecords('_%s._%s.%s' % (port, protocol.lower(), hostname), rrtype=52, secure=secure)
	except InsecureLookupException, e:
		print str(e)
		sys.exit(1)
	except DNSLookupError, e:
		print 'Unable to resolve %s: %s' % (hostname, str(e))
		sys.exit(1)
	ret = []
	for record in records:
		hexdata = b2a_hex(record)
		if port == '*':
			ret.append(TLSARecord('*._%s.%s' % (protocol.lower(), hostname), int(hexdata[0:2],16), int(hexdata[2:4],16), int(hexdata[4:6],16), hexdata[6:]))
		else:
			ret.append(TLSARecord('_%s._%s.%s' % (port, protocol.lower(), hostname), int(hexdata[0:2],16), int(hexdata[2:4],16), int(hexdata[4:6],16), hexdata[6:]))
	return ret

def loadCert(certificate):
	"""Returns an M2Crypto.X509.X509 object"""
	if isinstance(certificate, X509.X509):
		# nothing to be done :-)
		return certificate
	try:
		# Maybe we were passed a path
		return X509.load_cert(certificate)
	except:
		# Can't load the cert
		raise Exception('Unable to load certificate %s.' % certificate)

def verifyCertMatch(record, cert):
	"""
	Verify the certificate with the record.
	record should be a TLSARecord and cert should be a M2Crypto.X509.X509
	"""
	if not isinstance(cert, X509.X509):
		return
	if not isinstance(record, TLSARecord):
		return

	if record.selector == 1:
		certhash = getHash(cert.get_pubkey(), record.mtype)
	else:
		certhash = getHash(cert, record.mtype)

	if not certhash:
		return

	if certhash == record.cert:
		return True
	else:
		return False

def verifyCertNameWithHostName(cert, hostname, with_msg=False):
	"""Verify the name on the certificate with a hostname, we need this because we get the cert based on IP address and thusly cannot rely on M2Crypto to verify this"""
	if not isinstance(cert, X509.X509):
		return
	if not isinstance(hostname, str):
		return

	if hostname[-1] == '.':
		hostname = hostname[0:-1]

	# Ugly string comparison to see if the name on the ee-cert matches with the name provided on the commandline
	try:
		altnames_on_cert = cert.get_ext('subjectAltName').get_value()
	except:
		altnames_on_cert = ''
	if hostname in (str(cert.get_subject()) + altnames_on_cert):
		return True
	else:
		if with_msg:
			print 'WARNING: Name on the certificate (Subject: %s, SubjectAltName: %s) doesn\'t match requested hostname (%s).' % (str(cert.get_subject()), altnames_on_cert, hostname)
		return False

class TLSARecord:
	"""When instanciated, this class contains all the fields of a TLSA record.
	"""
	def __init__(self, name, usage, selector, mtype, cert):
		"""name is the name of the RR in the format: /^(_\d{1,5}|\*)\._(tcp|udp|sctp)\.([a-z0-9]*\.){2,}$/
		usage, selector and mtype should be an integer
		cert should be a hexidecimal string representing the certificate to be matched field
		"""
		try:
			self.rrtype = 52    # TLSA per https://www.iana.org/assignments/dns-parameters
			self.rrclass = 1    # IN
			self.name = str(name)
			self.usage = int(usage)
			self.selector = int(selector)
			self.mtype = int(mtype)
			self.cert = str(cert)
		except:
			raise Exception('Invalid value passed, unable to create a TLSARecord')

	def getRecord(self, generic=False):
		"""Returns the RR string of this TLSARecord, either in rfc (default) or generic format"""
		if generic:
			return '%s IN TYPE52 \# %s %s%s%s%s' % (self.name, (len(self.cert)/2)+3 , self._toHex(self.usage), self._toHex(self.selector), self._toHex(self.mtype), self.cert)
		return '%s IN TLSA %s %s %s %s' % (self.name, self.usage, self.selector, self.mtype, self.cert)

	def _toHex(self, val):
		"""Helper function to create hex strings from integers"""
		return "%0.2x" % val

	def isValid(self, raiseException=False):
		"""Check whether all fields in the TLSA record are conforming to the spec and check if the port, protocol and name are good"""
		err =[]
		try:
			if not 1 <= int(self.getPort()) <= 65535:
				err.append('Port %s not within correct range (1 <= port <= 65535)' % self.getPort())
		except:
			if self.getPort() != '*':
				err.append('Port %s not a number' % self.getPort())
		if not self.usage in [0,1,2,3]:
			err.append('Usage: invalid (%s is not one of 0, 1, 2 or 3)' % self.usage)
		if not self.selector in [0,1]:
			err.append('Selector: invalid (%s is not one of 0 or 1)' % self.selector)
		if not self.mtype in [0,1,2]:
			err.append('Matching Type: invalid (%s is not one of 0, 1 or 2)' % self.mtype)
		if not self.isNameValid():
			err.append('Name (%s) is not in the correct format: _portnumber._transportprotocol.hostname.dom.' % self.name)
		# A certificate length of 0 is accepted
		if self.mtype in [1,2] and len(self.cert) != 0:
			if not len(self.cert) == {1:64,2:128}[self.mtype]:
				err.append('Certificate for Association: invalid (Hash length does not match hash-type in Matching Type(%s))' % {1:'SHA-256',2:'SHA-512'}[self.mtype])
		if len(err) != 0:
			if not raiseException:
				return False
			else:
				msg = 'The TLSA record is invalid.'
				for error in err:
					msg += '\n\t%s' % error
				raise RecordValidityException(msg)
		else:
			return True

	def isNameValid(self):
		"""Check if the name if in the correct format"""
		if not re.match('^(_\d{1,5}|\*)\._(tcp|udp|sctp)\.([-a-z0-9]*\.){2,}$', self.name):
			return False
		return True

	def getProtocol(self):
		"""Returns the protocol based on the name"""
		return re.split('\.', self.name)[1][1:]

	def getPort(self):
		"""Returns the port based on the name"""
		if re.split('\.', self.name)[0][0] == '*':
			return '*'
		else:
			return re.split('\.', self.name)[0][1:]

class ARecord:
	"""An object representing an A Record (IPv4 address)"""
	def __init__(self, hostname, address):
		self.rrtype = 1
		self.hostname = hostname
		self.address = address

	def __str__(self):
		return self.address

	def isValid(self):
		try:
			IPv4Address(self.address)
			return True
		except:
			return False

class AAAARecord:
	"""An object representing an AAAA Record (IPv6 address)"""
	def __init__(self, hostname, address):
		self.rrtype = 28
		self.hostname = hostname
		self.address = address

	def __str__(self):
		return self.address

	def isValid(self):
		try:
			IPv6Address(self.address)
			return True
		except:
			return False

# Exceptions
class RecordValidityException(Exception):
	pass

class InsecureLookupException(Exception):
	pass

class DNSLookupError(Exception):
	pass

