from Crypto.Cipher import AES
from Crypto.Hash import MD5, SHA256, HMAC
from Crypto.Random import get_random_bytes
import math


class PaddingError(Exception):
	# We raise a padding error if padding is not valid.
	pass
class MACFailure(Exception):
	# We raise a MAC failure error if the locally computed
	# MAC does not match the MAC that has been recieved
	pass

class ISO9797_1_pad1:
	def __init__(self, block_length : int):
		self.block_length = block_length
		pass

	def add_padding(self, plaintext : bytes):
		"""
		Add padding to the plaintext as described in ISO9797 Pad Scheme 1. 
		
		:param plaintext: a bytes array containing an arbitrary-length plaintext
		:returns: the padded plaintext
		:rtype: a bytes array.
		"""
		if not isinstance(plaintext, bytes):
			raise TypeError("plaintext is not a bytearray")


		# compute the padding length
		pad_len = self.block_length - (len(plaintext) % self.block_length)
		# if the plaintext is already block aligned, we do not add padding
		if pad_len == self.block_length:
			pad_len = 0

		if plaintext == b'':
			pad_len = self.block_length

		# as we want a positive integer multiple of the N, we say that if the plaintext
		# is the empty string, we add a block of padding
		if plaintext == b'':
			pad_len = self.block_length

		padding = b'\x00' * pad_len
		padded_plaintext = plaintext + padding
		return padded_plaintext


	def remove_padding(self, padded_plaintext : bytes):
		"""
		Add padding to the plaintext as described in ISO9797 Pad Scheme 1. 
		
		:param plaintext: a bytes array containing an arbitrary-length plaintext
		:returns: the padded plaintext
		:rtype: a bytes array.
		"""

		N = len(padded_plaintext)
		#check if the padded plaintet is block aligned
		if N % self.block_length != 0:
			raise PaddingError()

		# go through the last block of the padded plaintext from the right,
		# as soon as we see a byte which is not equal to \x00 we know that we
		# have reached the end of the padding. If we don't see that we padded an
		# entire block of padding which is against the padding scheme so we raise
		# a padding error
		for i in range(self.block_length):
			if (padded_plaintext[N-i-1].to_bytes(1,'big')) != (0).to_bytes(1,'big'):
				plaintext = padded_plaintext[:N-i]
				break
			if i == (self.block_length - 1):
				#we are not in the case in which we had the empty string as plaintext and we
				#added an entire block of padding
				if len(padded_plaintext) != self.block_length:
					raise PaddingError()
				#now we know that the plaintext was the empty string
				else:
					plaintext = b''

		return plaintext

class ISO9797_1_pad2:
	def __init__(self, block_length : int):
		self.block_length = block_length

	def add_padding(self, plaintext : bytes):
		"""
		Add padding to the plaintext as described in ISO9797 Pad Scheme 2.
		 
		:param plaintext: a bytes array containing an arbitrary-length plaintext
		:returns: the padded plaintext
		:rtype: a bytes array.
		"""
		if not isinstance(plaintext, bytes):
			raise TypeError('plaintext is not a byte array')
		# append the byte \x80 to signify the beginning of the padding according to the standard
		middle_pad_plaintext = plaintext + b'\x80'
		# compute how many bytes still need to be added block align
		pad_len = self.block_length - (len(middle_pad_plaintext) % self.block_length)
		if pad_len == self.block_length:
			pad_len = 0

		# note that we can never be in the case of the "empty plaintext" considered in pad1 as we
		# always add this \x80 byte and we look how many bytes need to be added after this /x80 byte to block align
		padding = b'\x00' * pad_len
		padded_plaintext = middle_pad_plaintext + padding
		return padded_plaintext


	def remove_padding(self, padded_plaintext : bytes):
		'''
		Removes padding as described in ISO9797 Pad Scheme 2

		:param padded_plaintext: a bytes array containing a padded plaintext
		:returns: an unpadded plaintext
		:rtype: a bytes array.
		'''

		N = len(padded_plaintext)
		# check if the padded plaintext is block aligned
		if N % self.block_length != 0:
			raise PaddingError()
		# we check if we see a byte "0x80" somewhere, otherwise raise a padding error
		for i in range(self.block_length):
			# make sure that the only bytes in the padding are \x00
			if (padded_plaintext[N - i - 1].to_bytes(1, 'big')) == b'\x00':
				continue
			# go from right to left untill we see the byte \x80
			if (padded_plaintext[N - i - 1].to_bytes(1, 'big')) == b'\x80':
				plaintext = padded_plaintext[:N - i - 1]
				break
			# if we have a whole block length of padding we do not adhere the padding scheme
			# raise a padding error
			if i == N-1:
				raise PaddingError()
			# if we don't fall in any one of the previous if statements, we must have a non
			# zero byte and non \x80 byte being part of the padding and we don't adhere to the
			# padding scheme, raise a padding error
			else:
				raise PaddingError()

		return plaintext


class ISO9797_1_pad3:
	def __init__(self, block_length : int):
		self.block_length = block_length

	def add_padding(self, plaintext : bytes):
		"""
		Add padding to the plaintext as described in ISO9797 Pad Scheme 3. 
		:param plaintext: a bytes array containing an arbitrary-length plaintext
		:returns: the padded plaintext
		:rtype: a bytes array.
		"""
		# compute the padding length
		pad_len = self.block_length - (len(plaintext) % self.block_length)

		if pad_len == self.block_length:
			pad_len = 0
		# if the length of the plaintext is 0 as we want a positive multiple of the plaintext
		# we need to add a whole block of padding if the padding length is 0
		if len(plaintext) == 0:
			pad_len = self.block_length

		padded_plaintext = plaintext + b'\x00' * pad_len
		Lintbits = len(plaintext) * 8
		bytesblockLP = Lintbits.to_bytes(self.block_length, 'big')
		# append the block with the length encoding
		padded_plaintext = bytesblockLP + padded_plaintext
		return padded_plaintext



	def remove_padding(self, padded_plaintext : bytes):
		'''
		Removes padding as described in ISO9797 Pad Scheme 3

		:param padded_plaintext: a bytes array containing a padded plaintext
		:returns: an unpadded plaintext
		:rtype: a bytes array.
		'''
		# recover the length of the plaintext encoded in the first block
		len_unpadded = int.from_bytes(padded_plaintext[:self.block_length], 'big')
		#check if len_upadded was bit oriented indeed
		if len_unpadded % 8 != 0:
			raise PaddingError
        # remove the block with the length encoding
		plaintext1 = padded_plaintext[self.block_length:]
		# isolate the plaintext based on the length encoding
		plaintext2 = plaintext1[:math.ceil(len_unpadded/8)]
		# get the padding
		padding = plaintext1[math.ceil(len_unpadded / 8):]
		# check if the padding does not exceed the length of a block
		if len(padding) > self.block_length:
			raise PaddingError()
		# check if the padding only consists of "0x00" bytes
		for i in padding:
			if (i).to_bytes(1, 'big') != b'\x00':
				raise PaddingError()
		# check if the length of the plaintext in bytes is equal to the encoded length
		# of the plaintext in bytes
		if int(len_unpadded/8) != len(plaintext2):
			raise PaddingError()
		return plaintext2

class ISO9797_1_pad:
	pad_methods = {1: ISO9797_1_pad1, 2: ISO9797_1_pad2, 3: ISO9797_1_pad3}

	def __init__(self):
		pass

	def new(self, block_length : int, method : int):
		return pad_methods[method](block_length)

class ISO10116_CBC_AES:
	# CBC mode of operation according to the standard
	def __init__(self, key : bytes, block_length : int, padding_method : ISO9797_1_pad, iv : bytes =b''):
		self.block_length = block_length
		self.key = key
		self.padding_method = padding_method
		self.iv = iv

	def encrypt(self, plaintext : bytes):
		# Pad according to specified padding method
		padded_plaintext = self.padding_method(self.block_length).add_padding(plaintext)
		if self.iv == b'':
			iv = get_random_bytes(self.block_length)
		else:
			iv = self.iv

		# Encrypt plaintext under "key" using AES-128 in CBC
		cipher = AES.new(self.key, mode=AES.MODE_CBC, IV=iv)
		ciphertext = cipher.encrypt(padded_plaintext)
		return iv+ciphertext

	def decrypt(self, ciphertext : bytes):
		# Decrypt the ciphertext under key in AES-CBC mode
		iv = ciphertext[:self.block_length]
		ciphertext = ciphertext[self.block_length:]
		cipher = AES.new(self.key, mode=AES.MODE_CBC, IV=iv)
		padded_plaintext = cipher.decrypt(ciphertext)
		plaintext = self.padding_method(self.block_length).remove_padding(padded_plaintext)
		return plaintext

class mac_then_encrypt_wrapper:
	def __init__(self, master_secret : bytes, block_length : int, iv : bytes =b''):
		self.block_length = block_length
		self.key_length = 16
		self.enc_key, self.mac_key = self.kdf(master_secret)
		self.cipher = ISO10116_CBC_AES(self.enc_key, block_length, ISO9797_1_pad3, iv=iv)
		self.digest = MD5
		self.mac_length = self.digest.digest_size

	def kdf(self, ms : bytes):
		kdf = SHA256.new()
		kdf.update(ms)
		key_material = kdf.digest()
		enc_key = key_material[:self.key_length]
		mac_key = key_material[self.key_length:]
		return enc_key, mac_key

	def add_mac(self, message : bytes, key : bytes):
		hash = HMAC.new(key, digestmod=self.digest)
		hash.update(message)
		mac = hash.digest()
		auth_message = mac + message
		return auth_message

	def check_and_remove_mac(self, message : bytes):
		hash = HMAC.new(self.mac_key, digestmod=self.digest)
		recd_mac = message[:self.mac_length]
		plaintext = message[self.mac_length:]
		hash.update(plaintext)
		comp_mac = hash.digest()
		if recd_mac != comp_mac:
			raise MACFailure()
		return plaintext

	def encrypt(self, plaintext : bytes):
		authenticated = self.add_mac(plaintext, self.mac_key)
		return self.cipher.encrypt(authenticated)

	def decrypt(self, ciphertext : bytes):
		authenticated = self.cipher.decrypt(ciphertext)
		plaintext = self.check_and_remove_mac(authenticated)
		return plaintext





