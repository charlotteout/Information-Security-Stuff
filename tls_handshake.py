#!/usr/bin/env python

'''
tls_handshake.py:
Implementation of the TLS 1.3 Handshake Protocol
'''

from Crypto.Hash import SHA256, SHA384
from Crypto.Random import get_random_bytes
import tls_crypto
import tls_constants
from tls_error import *
import tls_extensions

class Handshake:
	"This is the class for the handshake protocol"

	def __init__(self, csuites, extensions, role):
		self.csuites = csuites
		self.extensions = extensions
		self.state = tls_constants.INIT_STATE
		self.role = role
		self.neg_group = None
		self.neg_version = None
		self.ec_sec_keys = {}
		self.remote_hs_traffic_secret = None
		self.local_hs_traffic_secret = None
		self.transcript = "".encode()

	def tls_13_compute_local_hs_key_iv(self):
		if (self.local_hs_traffic_secret == None):
			raise StateConfusionError()
		handshake_key, handshake_iv = tls_crypto.tls_derive_key_iv(self.csuite, self.local_hs_traffic_secret)
		return handshake_key, handshake_iv, self.csuite

	def tls_13_compute_remote_hs_key_iv(self):
		if (self.remote_hs_traffic_secret == None):
			raise StateConfusionError()
		handshake_key, handshake_iv = tls_crypto.tls_derive_key_iv(self.csuite, self.remote_hs_traffic_secret)
		return handshake_key, handshake_iv, self.csuite

	def tls_13_compute_local_ap_key_iv(self):
		if (self.local_ap_traffic_secret == None):
			raise StateConfusionError()
		application_key, application_iv = tls_crypto.tls_derive_key_iv(self.csuite, self.local_ap_traffic_secret)
		return application_key, application_iv, self.csuite

	def tls_13_compute_remote_ap_key_iv(self):
		if (self.remote_ap_traffic_secret == None):
			raise StateConfusionError()
		application_key, application_iv = tls_crypto.tls_derive_key_iv(self.csuite, self.remote_ap_traffic_secret)
		return application_key, application_iv, self.csuite

	def attach_handshake_header(self, msg_type, msg):
		len_msg = len(msg).to_bytes(3, 'big')
		hs_msg_type = msg_type.to_bytes(1, 'big')
		return hs_msg_type + len_msg + msg

	def process_handshake_header(self, msg_type, msg):
		curr_pos = 0
		curr_msg_type = msg[curr_pos]
		if (curr_msg_type != msg_type):
			raise InvalidMessageStructureError()
		curr_pos = curr_pos + tls_constants.MSG_TYPE_LEN
		msg_len = int.from_bytes(msg[curr_pos:curr_pos + tls_constants.MSG_LEN_LEN], 'big')
		curr_pos = curr_pos + tls_constants.MSG_LEN_LEN
		ptxt_msg = msg[curr_pos:]
		if (msg_len != len(ptxt_msg)):
			raise InvalidMessageStructureError()
		return ptxt_msg

	def tls_13_client_hello(self):
		legacy_vers = tls_constants.LEGACY_VERSION.to_bytes(2, 'big') #they agree on this
		random = get_random_bytes(tls_constants.RANDOM_LEN)
		legacy_sess_id = get_random_bytes(tls_constants.RANDOM_LEN)
		legacy_sess_id_len = len(legacy_sess_id).to_bytes(tls_constants.SID_LEN_LEN, 'big')
		csuites_bytes = self.csuites[0].to_bytes(tls_constants.CSUITE_LEN, 'big')
		for i in range(1,len(self.csuites)):
			csuites_bytes = csuites_bytes + self.csuites[i].to_bytes(tls_constants.CSUITE_LEN,"big")
		csuite_len_bytes = len(csuites_bytes).to_bytes(tls_constants.CSUITE_LEN_LEN, 'big')
		legacy_compression_len = (1).to_bytes(1,'big')
		legacy_compression = (0x00).to_bytes(1, 'big')
		supported_versions = tls_extensions.prep_support_vers_ext(self.extensions)
		group_ext = tls_extensions.prep_support_groups_ext(self.extensions)
		keyshare_ext, self.ec_sec_keys = tls_extensions.prep_keyshare_ext(self.extensions)
		signature_ext = tls_extensions.prep_signature_ext(self.extensions)
		extensions = supported_versions + group_ext + keyshare_ext + signature_ext
		exten_len = len(extensions).to_bytes(2, 'big')
		msg = legacy_vers + random + legacy_sess_id_len + legacy_sess_id + csuite_len_bytes + csuites_bytes + legacy_compression_len + legacy_compression + exten_len + extensions
		chelo_msg = self.attach_handshake_header(tls_constants.CHELO_TYPE, msg)
		self.transcript = self.transcript + chelo_msg
		return chelo_msg


	def tls_13_process_client_hello(self, chelo_msg):
		# DECONSTRUCT OUR CLIENTHELLO MESSAGE
		chelo = self.process_handshake_header(tls_constants.CHELO_TYPE, chelo_msg)
		curr_pos = 0
		chelo_vers = chelo[curr_pos:curr_pos + tls_constants.MSG_VERS_LEN]
		curr_pos = curr_pos + tls_constants.MSG_VERS_LEN
		chelo_rand = chelo[curr_pos:curr_pos + tls_constants.RANDOM_LEN]
		curr_pos = curr_pos + tls_constants.RANDOM_LEN
		chelo_sess_id_len = chelo[curr_pos]
		curr_pos = curr_pos + tls_constants.SID_LEN_LEN
		self.sid = chelo[curr_pos:curr_pos+chelo_sess_id_len]
		curr_pos = curr_pos+chelo_sess_id_len
		csuites_len = int.from_bytes(chelo[curr_pos:curr_pos+tls_constants.CSUITE_LEN_LEN], 'big')
		curr_pos = curr_pos + tls_constants.CSUITE_LEN_LEN
		self.remote_csuites = chelo[curr_pos:curr_pos+csuites_len]
		curr_pos = curr_pos + csuites_len
		self.num_remote_csuites = csuites_len//tls_constants.CSUITE_LEN
		comp_len = int.from_bytes(chelo[curr_pos:curr_pos+tls_constants.COMP_LEN_LEN], 'big')
		curr_pos = curr_pos + tls_constants.COMP_LEN_LEN
		legacy_comp = chelo[curr_pos]
		if (legacy_comp != 0x00):
			alert_msg = tls_prepare_alert(tls_constants.TLS_ILLEGAL_PARA)
			print("Invalid Legacy Compression Field")
			return alert_msg
		curr_pos = curr_pos + comp_len
		exts_len = int.from_bytes(chelo[curr_pos:curr_pos+tls_constants.EXT_LEN_LEN], 'big')
		curr_pos = curr_pos + tls_constants.EXT_LEN_LEN
		self.remote_extensions = chelo[curr_pos:]
		self.transcript = self.transcript + chelo_msg
		return 0

	def tls_13_server_hello(self, chelo):
		try:
			if (self.state != tls_constants.INIT_STATE):
				raise StateConfusionError()
			if (self.role != tls_constants.SERVER_FLAG):
				raise WrongRoleError()
			result = self.tls_13_process_client_hello(chelo)
			if (result != 0):
				return (1, result)
			curr_ext_pos = 0
			while (curr_ext_pos < len(self.remote_extensions)):
				ext_type = int.from_bytes(self.remote_extensions[curr_ext_pos:curr_ext_pos+2], 'big')
				curr_ext_pos = curr_ext_pos + 2
				ext_len = int.from_bytes(self.remote_extensions[curr_ext_pos:curr_ext_pos+2], 'big')
				curr_ext_pos = curr_ext_pos + 2
				ext_bytes = self.remote_extensions[curr_ext_pos:curr_ext_pos+ext_len]
				if (ext_type == tls_constants.SUPPORT_VERS_TYPE):
					self.neg_version = tls_extensions.negotiate_support_vers_ext(self.extensions, ext_bytes)
				if (ext_type == tls_constants.SUPPORT_GROUPS_TYPE):
					self.neg_group = tls_extensions.negotiate_support_group_ext(self.extensions, self.neg_group, ext_len//2, ext_bytes)
				if (ext_type == tls_constants.KEY_SHARE_TYPE):
					supported_keyshare, self.neg_group, self.ec_pub_key, self.ec_sec_key = tls_extensions.negotiate_keyshare_ext(self.extensions, self.neg_group, ext_len, ext_bytes)
				if (ext_type == tls_constants.SIG_ALGS_TYPE):
					supported_signature = tls_extensions.negotiate_signature_ext(self.extensions, ext_bytes)
					self.signature = supported_signature
				curr_ext_pos = curr_ext_pos + ext_len
			legacy_vers = tls_constants.LEGACY_VERSION.to_bytes(2, 'big') # Must be set like this for compatability reasons
			random = get_random_bytes(32) # Must be set like this for compatability reasons
			legacy_sess_id = self.sid # Must be set like this for compatability reasons
			legacy_sess_id_len = len(self.sid).to_bytes(1, 'big')
			legacy_compression = (0x00).to_bytes(1, 'big')
			# AT THIS POINT WE NEGOTIATE A COMMONLY-SUPPORTED CIPHERSUITE
			self.csuite = tls_extensions.negotiate_support_csuite(self.csuites, self.num_remote_csuites, self.remote_csuites)
			csuite_bytes = self.csuite.to_bytes(2, 'big')
			# WE ATTACH ALL OUR EXTENSIONS
			neg_vers_ext = tls_extensions.finish_support_vers_ext(self.neg_version)
			neg_group_ext = tls_extensions.finish_support_group_ext(self.neg_group)
			extensions = neg_vers_ext + neg_group_ext + supported_keyshare
			exten_len = len(extensions).to_bytes(2, 'big')
			msg = legacy_vers + random + legacy_sess_id_len + legacy_sess_id + csuite_bytes + legacy_compression + exten_len + 	extensions
			shelo_msg = self.attach_handshake_header(tls_constants.SHELO_TYPE, msg)
			self.transcript = chelo + shelo_msg
			early_secret = tls_crypto.tls_extract_secret(self.csuite, None, None)
			derived_early_secret = tls_crypto.tls_derive_secret(self.csuite, early_secret, "derived".encode(), "".encode())
			ecdh_secret_point = tls_crypto.ec_dh(self.ec_sec_key, self.ec_pub_key)
			ecdh_secret = tls_crypto.point_to_secret(ecdh_secret_point, self.neg_group)
			handshake_secret = tls_crypto.tls_extract_secret(self.csuite, ecdh_secret,derived_early_secret)
			self.local_hs_traffic_secret = tls_crypto.tls_derive_secret(self.csuite, handshake_secret, "s hs traffic".encode(), self.transcript)
			self.remote_hs_traffic_secret = tls_crypto.tls_derive_secret(self.csuite, handshake_secret, "c hs traffic".encode(), self.transcript)
			derived_hs_secret = tls_crypto.tls_derive_secret(self.csuite, handshake_secret, "derived".encode(), "".encode())
			self.master_secret = tls_crypto.tls_extract_secret(self.csuite, None, derived_hs_secret)
			return (0, shelo_msg)
		except (NoCommonVersionError):
			alert_msg = tls_prepare_alert(tls_constants.TLS_HS_FAIL)
			return alert_msg

	def tls_13_process_server_hello(self, shelo_msg):
		shelo = self.process_handshake_header(tls_constants.SHELO_TYPE, shelo_msg)
		curr_pos = 0
		shelo_vers = shelo[curr_pos:curr_pos + tls_constants.MSG_VERS_LEN]
		curr_pos = curr_pos + tls_constants.MSG_VERS_LEN
		shelo_rand = shelo[curr_pos:curr_pos + tls_constants.RANDOM_LEN]
		curr_pos = curr_pos + tls_constants.RANDOM_LEN
		shelo_sess_id_len = int.from_bytes(shelo[curr_pos: curr_pos + tls_constants.SID_LEN_LEN],'big')
		#print("shelo_sess_id_len", shelo_sess_id_len)
		curr_pos = curr_pos + tls_constants.SID_LEN_LEN
		self.sid = shelo[curr_pos:curr_pos + shelo_sess_id_len]
		curr_pos = curr_pos + shelo_sess_id_len

		self.csuite = int.from_bytes(shelo[curr_pos:curr_pos + tls_constants.CSUITE_LEN],'big')
		curr_pos = curr_pos + tls_constants.CSUITE_LEN
		comp_len = int.from_bytes(shelo[curr_pos:curr_pos + tls_constants.COMP_LEN_LEN], 'big')
		curr_pos = curr_pos + tls_constants.COMP_LEN_LEN
		legacy_comp = shelo[curr_pos]
		if (legacy_comp != 0x00):
			alert_msg = tls_prepare_alert(tls_constants.TLS_ILLEGAL_PARA)
			print("Invalid Legacy Compression Field")
			return alert_msg
		curr_pos = curr_pos + comp_len
		exts_len = int.from_bytes(shelo[curr_pos:curr_pos+tls_constants.EXT_LEN_LEN], 'big')
		curr_pos = curr_pos + tls_constants.EXT_LEN_LEN

		stoppoint = curr_pos + exts_len

		while (curr_pos < stoppoint):
			ext_type = int.from_bytes(shelo[curr_pos:curr_pos+2], 'big')
			curr_pos = curr_pos + 2
			if (ext_type == tls_constants.SUPPORT_VERS_TYPE):
				support_vers_len = int.from_bytes(shelo[curr_pos:curr_pos + 2], 'big')
				curr_pos = curr_pos + 2
				self.neg_version = int.from_bytes(shelo[curr_pos: curr_pos+ support_vers_len], 'big')
				curr_pos = curr_pos + support_vers_len
			if (ext_type == tls_constants.SUPPORT_GROUPS_TYPE):
				support_group_len = int.from_bytes(shelo[curr_pos:curr_pos + 2], 'big')
				curr_pos = curr_pos + 2
				self.neg_group = int.from_bytes(shelo[curr_pos: curr_pos + support_group_len], 'big')
				curr_pos = curr_pos + support_group_len
			if (ext_type == tls_constants.KEY_SHARE_TYPE):
				exch_len = int.from_bytes(shelo[curr_pos:curr_pos + 2], 'big')
				curr_pos = curr_pos + 2
				name_group = int.from_bytes(shelo[curr_pos: curr_pos+2], 'big')
				curr_pos = curr_pos + 2
				len_pub_key = int.from_bytes(shelo[curr_pos: curr_pos+2], 'big')
				curr_pos = curr_pos + 2
				leg_len = int.from_bytes(shelo[curr_pos : curr_pos + 1], 'big')
				curr_pos = curr_pos + 1
				pub_bytes = shelo[curr_pos:curr_pos + len_pub_key-1]
				self.ec_pub_key = tls_crypto.convert_x_y_bytes_ec_pub(pub_bytes, name_group)
				curr_pos = curr_pos + len_pub_key -1

		self.transcript = self.transcript + shelo_msg
		ec_sec_key = self.ec_sec_keys[name_group]
		ecdh_secret_point = tls_crypto.ec_dh(ec_sec_key, self.ec_pub_key)
		ecdh_secret = tls_crypto.point_to_secret(ecdh_secret_point, self.neg_group)


		self.early_secret = tls_crypto.tls_extract_secret(self.csuite, None, None)
		derived_early_secret = tls_crypto.tls_derive_secret(self.csuite, self.early_secret, "derived".encode(), "".encode())
		self.handshake_secret = tls_crypto.tls_extract_secret(self.csuite, ecdh_secret, derived_early_secret)
		self.local_hs_traffic_secret = tls_crypto.tls_derive_secret(self.csuite, self.handshake_secret,
																	"c hs traffic".encode(), self.transcript)
		self.remote_hs_traffic_secret = tls_crypto.tls_derive_secret(self.csuite, self.handshake_secret,
																	 "s hs traffic".encode(), self.transcript)
		derived_hs_secret = tls_crypto.tls_derive_secret(self.csuite, self.handshake_secret, "derived".encode(), "".encode())
		self.master_secret = tls_crypto.tls_extract_secret(self.csuite, None, derived_hs_secret)





	def tls_13_server_enc_ext(self):
		msg = 0x0000.to_bytes(2, 'big')
		enc_ext_msg = self.attach_handshake_header(tls_constants.ENEXT_TYPE, msg)
		self.transcript = self.transcript + enc_ext_msg
		return enc_ext_msg

	def tls_13_process_enc_ext(self, enc_ext_msg):
		enc_ext = self.process_handshake_header(tls_constants.ENEXT_TYPE, enc_ext_msg)
		if (enc_ext != 0x0000.to_bytes(2, 'big')):
			raise InvalidMessageStructureError
		self.transcript = self.transcript + enc_ext_msg

	def tls_13_server_cert(self):
		certificate = tls_constants.SERVER_SUPPORTED_CERTIFICATES[self.signature]
		certificate_bytes = certificate.encode()
		cert_extensions = (0x0000).to_bytes(2, 'big')
		cert_len = (len(certificate_bytes) + len(cert_extensions)).to_bytes(3, 'big')
		cert_chain_len = (len(certificate_bytes) + len(cert_extensions) + len(cert_len)).to_bytes(3, 'big')
		cert_context_len = (0x00).to_bytes(1, 'big')
		msg = cert_context_len + cert_chain_len + cert_len + certificate_bytes + cert_extensions
		cert_msg = self.attach_handshake_header(tls_constants.CERT_TYPE, msg)
		self.transcript = self.transcript + cert_msg
		return cert_msg

	def tls_13_process_server_cert(self, cert_msg):
		cert = self.process_handshake_header(tls_constants.CERT_TYPE, cert_msg)
		msg_len = len(cert)
		curr_pos = 0
		cert_context_len = cert[curr_pos]
		curr_pos = curr_pos + 1
		if (cert_context_len != 0):
			cert_context = cert_msg[curr_pos:curr_pos + cert_context_len]
		curr_pos = curr_pos + cert_context_len
		while (curr_pos < msg_len):
			cert_chain_len = int.from_bytes(cert[curr_pos: curr_pos + 3], 'big')
			curr_pos = curr_pos + 3
			cert_chain = cert[curr_pos:curr_pos+cert_chain_len]
			curr_chain_pos = 0
			while (curr_chain_pos < cert_chain_len):
				cert_len = int.from_bytes(cert_chain[curr_chain_pos: curr_chain_pos + 3], 'big')
				curr_chain_pos = curr_chain_pos + 3
				self.server_cert = cert_chain[curr_chain_pos:curr_chain_pos + cert_len - 2]
				self.server_cert_string = self.server_cert.decode('utf-8')
				# SUBTRACT TWO FOR THE EXTENSIONS, WHICH WILL ALWAYS BE EMPTY
				curr_chain_pos = curr_chain_pos + cert_len
			curr_pos = curr_pos + cert_chain_len
		self.transcript = self.transcript + cert_msg

	def tls_13_server_cert_verify(self):
		transcript_hash = tls_crypto.tls_transcript_hash(self.csuite, self.transcript)
		signature = tls_crypto.tls_signature(self.signature, transcript_hash, tls_constants.SERVER_FLAG)
		len_sig_bytes = len(signature).to_bytes(2, 'big')
		sig_type_bytes = self.signature.to_bytes(2, 'big')
		msg = sig_type_bytes + len_sig_bytes + signature
		cert_verify_msg = self.attach_handshake_header(tls_constants.CVFY_TYPE, msg)
		self.transcript = self.transcript + cert_verify_msg
		return cert_verify_msg

	def tls_13_process_server_cert_verify(self, verify_msg):
		verify = self.process_handshake_header(tls_constants.CVFY_TYPE, verify_msg)
		curr_pos = 0
		signature_algorithm = verify[curr_pos: curr_pos + 2]
		signature = verify[curr_pos+2:]
		signature_alg_int = int.from_bytes(signature_algorithm,'big')
		if (signature_alg_int == tls_constants.RSA_PKCS1_SHA256 or signature_alg_int == tls_constants.RSA_PKCS1_SHA384):
			public_key = tls_crypto.get_rsa_pk_from_cert(self.server_cert_string)
		else:
			public_key = tls_crypto.get_ecdsa_pk_from_cert(self.server_cert_string)
		transcript_hash = tls_crypto.tls_transcript_hash(self.csuite, self.transcript)
		try:
			tls_crypto.tls_verify_signature(signature_algorithm, transcript_hash, tls_constants.SERVER_FLAG, signature, public_key)
			self.transcript = self.transcript + verify_msg
		except ValueError:
			print("invalid signature")


	def tls_13_finished(self):
		transcript_hash = tls_crypto.tls_transcript_hash(self.csuite, self.transcript)
		finished_key = tls_crypto.tls_finished_key_derive(self.csuite, self.local_hs_traffic_secret)
		tag = tls_crypto.tls_finished_mac(self.csuite, finished_key, transcript_hash)
		fin_msg = self.attach_handshake_header(tls_constants.FINI_TYPE, tag)
		self.transcript = self.transcript + fin_msg
		if (self.role == tls_constants.SERVER_FLAG):
			transcript_hash = tls_crypto.tls_transcript_hash(self.csuite, self.transcript)
			self.local_ap_traffic_secret = tls_crypto.tls_derive_secret(self.csuite, self.master_secret, "s ap traffic".encode(), transcript_hash)
			self.remote_ap_traffic_secret = tls_crypto.tls_derive_secret(self.csuite, self.master_secret, "c ap traffic".encode(), transcript_hash)
		return fin_msg

	def tls_13_process_finished(self, fin_msg):
		fin = self.process_handshake_header(tls_constants.FINI_TYPE, fin_msg)
		finished_key = tls_crypto.tls_finished_key_derive(self.csuite, self.remote_hs_traffic_secret)
		transcript_hash = tls_crypto.tls_transcript_hash(self.csuite, self.transcript)
		tls_crypto.tls_finished_mac_verify(self.csuite, finished_key, transcript_hash, fin)
		try:
			tls_crypto.tls_finished_mac_verify(self.csuite, finished_key, transcript_hash, fin)
			self.transcript = self.transcript + fin_msg
		except ValueError:
			print("invalid fin message")

		if (self.role == tls_constants.CLIENT_FLAG):
			transcript_hash = tls_crypto.tls_transcript_hash(self.csuite, self.transcript)
			self.local_ap_traffic_secret = tls_crypto.tls_derive_secret(self.csuite, self.master_secret, "s ap traffic".encode(), transcript_hash)
			self.remote_ap_traffic_secret = tls_crypto.tls_derive_secret(self.csuite, self.master_secret, "c ap traffic".encode(), transcript_hash)



	def tls_hs_ms_process(self, msg):
		msg_type = msg[0]
		response = 0
		if (self.role == tls_constants.CLIENT_FLAG):
			if (msg_type == tls_constants.CHELO_TYPE) or (msg_type == tls_constants.EOED_TYPE):
				return UnexpectedMessageError()
		if (self.role == tls_constants.SERVER_FLAG):
			if (msg_type == tls_constants.SHELO_TYPE) or (msg_type == tls_constants.CREQ_TYPE):
				return UnexpectedMessageError()
		if (msg_type == tls_constants.CHELO_TYPE):
			response = self.tls_13_server_hello(msg)
		return response
