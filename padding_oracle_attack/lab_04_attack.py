from lab_04_cryptolib import *
from Crypto.Random import get_random_bytes

import private.oracle as o

MAC_LENGTH = 32


# helper functions
def xor_value_at_pos(bytes_string: bytes, pos: int, value: int):
    xor_byte = bytes_string[pos] ^ value
    return bytes_string[:pos] + bytes([xor_byte]) + bytes_string[pos + 1:]


def xor_bytes(bytes_string_a: bytes, bytes_string_b: bytes):
    return bytes([ba ^ bb for ba, bb in zip(bytes_string_a, bytes_string_b)])


def ld_repr(pt_len: int, block_length: int):
    return (pt_len).to_bytes(block_length, 'big')


def xor_bit(pt: bytes, loc: int, bit: int):
    set_byte = pt[loc // 8] ^ bit << (7 - (loc % 8))
    return pt[:loc // 8] + bytes([set_byte]) + pt[1 + (loc // 8):]


def chunk(bytestring: bytes, block_length: int):
    curr = -1
    limit = len(bytestring) // block_length
    while curr < limit - 1:
        curr = curr + 1
        yield bytestring[curr * block_length:(curr + 1) * block_length]


# attack code
class padding_oracle_attack():
    def __init__(self, oracle):
        self.ORACLE = oracle

    def padding_oracle(self, ciphertext: bytes):
        try:
            self.ORACLE.decrypt(ciphertext)
        except MACFailure:
            return True
        except PaddingError:
            return False
        return True

    def recover_ld(self, ct: bytes, block_length: int):
        """
        Use ``padding_oracle`` to recover the length of the underlying
        plaintext.

        :param ct: a bytes array containing a full MEE ciphertext
        encrypted using AES-CBC with ISO9797_1_pad3 padding.
        :param block_length: an integer containing the block length of AES.

        :returns: the length of the plaintext in bits.

        :rtype: an integer.
        """
        # GENERAL IDEA: we start flipping (xoring with all possile values) bytes in the second last block of the ciphertext
        # we note that xoring  a byte in position i of the second last block with a byte x corresponds to xoring a
        # byte in the plaintext of the last block in position i with byte x.
        # Hence, our strategy is to start from the leftmost byte in the second last cipher block and to start xoring bytes
        # with (in this case \x01 but any byte not equal to \x00 would work). Then, as long as we flip a byte in position j
        # and position j of the last block is part of the padding, we xor \x00 by \x01 resulting in \x01. Hence, the padding
        # oracle will complain. The first time the oracle complains is the first time we flip a padding byte.
        # hence, we have recovered the length of the plaintext!
        num_blocks = int(len(ct)/block_length)
        # we note that the ciphertext can never be less than 3 blocks as it always consists of the IV, ct0 (the length encoding)
        # and the MAC. If the number of blocks is exactly 3 it means that we had the empty plaintext. We do however
        # see the MAC as part of the plaintext when it comes to the length
        if num_blocks == 3:
            ld = block_length*8
            return ld

        # we define the first byte of the second last block as the point from where we start byte flipping
        interestingpoint = (num_blocks - 2) * block_length
        ld = -1

        for i in range(block_length):
            flipped_ciphertext = xor_value_at_pos(ct, pos= interestingpoint+ i, value=1)

            if self.padding_oracle(flipped_ciphertext) == False:
                # this is the first time where we are flipping a byte in the
                # ciphertext which results in a byte flip in the plaintext which
                # is part of the padding, hence we do not have a valid padding anymore
                # in doing so we can thus discover the length
                ld = (interestingpoint - block_length + i)*8
                break
        # note that this if statement is only true when the padding oracle never returned false
        # this is only the case when we do not have padding; the plaintext was block aligned already
        # hence, then we know that the last block was only plaintext and we know the lenght of the plaintext as well
        if ld == -1:
            ld = interestingpoint * 8
        return ld


    def recover_byte(self,
                     iv: bytes,
                     ct0: bytes,
                     pre_target: bytes,
                     target: bytes,
                     current_ld: int,
                     target_byte_no: int,
                     block_length: int):
        """
        Use ``padding_oracle`` to perform a recovery of a single byte.

        :param iv: a byte array containing the initialisation vector block
        :param ct0: a byte array containing the first ciphertext
        block, encrypted using AES-CBC with ISO9797_1_pad3 padding.
        :param pre_target: a byte array containing the previous ciphertext
        block relative to the recovered byte, encrypted using AES-CBC
        with ISO9797_1_pad3 padding.
        :param target: a byte array of the ciphertext block containing the
        byte to recover, encrypted using AES-CBC with ISO9797_1_pad3 padding.
        :param current_ld: an integer representing the byte-length of the
        underlying unpadded plaintext
        :param target_byte_no: an integer representing the position of the
        plaintext byte to recover, indexed by 0.
        :param block_length: an integer containing the block length of AES.

        :returns: the plaintext byte associated with position target_byte_pos.
        :rtype: a character.
        """
        # STEP1 determine the new length it should encode!
        # our construction of the cipertext we will submit to the padding oracle will be as follows
        # we will first add the (modified) IV, C0, pre-target and target block.
        # hence, if we want to recover say the third byte of the cipher target block, we should set the length of the
        # plaintext as blocklength (the length of the pre-target block) + (target_byte_no - 1), as the target byte no
        # should be the first byte of the plaintext.
        new_ld = (block_length + target_byte_no -1 + 1) * 8
        old_ld = current_ld
        new_ld_bytes = (new_ld).to_bytes(block_length, 'big')
        old_ld_bytes = (old_ld).to_bytes(block_length, 'big')
        intermediate = xor_bytes(new_ld_bytes, old_ld_bytes)
        IVprime = xor_bytes(intermediate, iv)

        # this we will xor and then send to the padding oracle
        CTI = IVprime + ct0 + pre_target + target

        #STEP2 xor the byte_pos_no byte in pre-target to xor the byte pos_no in the target plaintext
        xor_pos = 2* block_length + target_byte_no
        for i in range(256):
            CTI_xor = xor_value_at_pos(bytes_string=CTI, pos=xor_pos, value=i)
            # we check when the padding oracle returns true. Namely, then we have xored with the byte which is equal
            # to the to be recovered byte (hence we have found the to be recovered byte).
            if self.padding_oracle(ciphertext=CTI_xor) == True:
                recovered_byte = i
                break
            else:
                continue
        return recovered_byte

    def recover_leftmost_byte(self,
                              iv: bytes,
                              ct0: bytes,
                              pre_target: bytes,
                              target: bytes,
                              current_ld: int,
                              target_byte_no: int,
                              block_length: int):
        """
        Use ``padding_oracle`` to perform a recovery of a single byte.
        Note that your attack may not need all of the available parameters.

        :param iv: a byte array containing the initialisation vector block
        :param ct0: a byte array containing the first ciphertext
        block, encrypted using AES-CBC with ISO9797_1_pad3 padding.
        :param pre_target: a byte array containing the previous ciphertext
        block relative to the recovered byte, encrypted using AES-CBC
        with ISO9797_1_pad3 padding.
        :param target: a byte array of the ciphertext block containing the
        byte to recover, encrypted using AES-CBC with ISO9797_1_pad3 padding.
        :param current_ld: an integer representing the byte-length of the
        underlying unpadded plaintext
        :param target_byte_no: always 0.
        :param block_length: an integer containing the block length of AES.
        :returns: the leftmost plaintext byte associated with
        position target_byte_pos.

        :rtype: a character.
        """

        # STEP1: define IVprime. Define different versions brute force over the first
        # by assumption that all the right plaintext bytes are equal to 0, so we don't have do to this
        # plaintext recovery here!
        IVprime1 = xor_bytes(pre_target, (8*block_length).to_bytes(block_length, 'big'))

        # STEP2: we note that in this ciphertext construction target functions as the length encoding
        # and the random bytes are the plaintext (or the mac tag but the length of the mac tag adds to the length of the plaintext)
        # Hence, the padding oracle only accepts when we have the correct length encoding, hence when target is the byte representation
        # of the block length * 8 (block length in bits). We note that the target encodes this when we xor the first
        # byte of the IVprime by the byte equal to the to be recovered byte (as then this byte is 0, by assumption all other
        # bytes are 0 and we xor by n (in byte representation) afterwards
        for i in range(256):
            IVprime = xor_value_at_pos(bytes_string=IVprime1, pos=0, value=i)
            ciph = IVprime + target + get_random_bytes(block_length)

            # if the padding oracle accepts, we have xored with the same byte as the
            # byte to be found
            if self.padding_oracle(ciph) == True:
                recovered_byte = i
                break
        return recovered_byte




    def recover_pt(self, ct: bytes, block_length: int):
        """
        Use ``padding_oracle`` to perform a full plaintext recovery.
        Can use ``recover_byte'' and ``recover_leftmost_byte''
        as subroutines.

        :param ct: a byte array containing a full MEE ciphertext
        encrypted using AES-CBC with ISO9797_1_pad3 padding.
        :param block_length: an integer containing the block length of AES.

        :returns: the underlying plaintext

        :rtype: a string
        """
        num_blocks = int(len(ct)/block_length)

        # store the IV and ct0 (length encoding block)
        IV = ct[:block_length]
        ct0 = ct[block_length:2*block_length]
        # Recover the length of the plaintext (in bits) using the above defined recover_ld function
        ld = self.recover_ld(ct=ct, block_length=block_length)
        # convert the ld to the length in bytes
        ld_bytes = int(ld/8)
        # compute the length of the padding (we will remove the padding later)
        padding_length = block_length - (ld_bytes % block_length)
        if padding_length == block_length:
            padding_length = 0

        rec_plaintext_block = b''

        # loop over all the blocks
        # We first use the function recover_bytes to recover all bytes but the leftmost one
        # Then and the end of each block we recover the leftmost byte. Note that we also recover the
        # padding here, but afterwards we can get rid of the padding as we computed the padding length
        for b in range(num_blocks, 3,-1):
            target = ct[(b-1)*block_length:b*block_length]
            pre_target = ct[(b-2)*block_length: (b-1)*block_length]
            #now recover all the bytes within a block
            for pos in range(block_length-1, 0,-1):
                # recover the byte
                rec_plaintext_byte_int = self.recover_byte(iv=IV, ct0=ct0, pre_target=pre_target,
                                                           target=target, current_ld=ld, target_byte_no=pos, block_length=block_length)
                rec_plaintext_byte = (rec_plaintext_byte_int).to_bytes(1,'big')
                # update the recovered plaintext
                rec_plaintext_block = rec_plaintext_byte + rec_plaintext_block
                # xor the pre_target with the recovered byte such that in the plaintext we get a 0 in the position
                # we just recovered
                pre_target = xor_bytes(pre_target, pos*b'\x00' + rec_plaintext_byte + (block_length - pos)*b'\x00')
            # Recover the leftmost byte
            leftmost_byte_int = self.recover_leftmost_byte(iv=IV, ct0=ct0, pre_target=pre_target,
                                                           target=target, target_byte_no=0, current_ld=ld, block_length=block_length)
            leftmost_byte = (leftmost_byte_int).to_bytes(1, 'big')

            rec_plaintext_block = leftmost_byte + rec_plaintext_block
        # get rid of the padding if needed
        if padding_length == 0:
            return rec_plaintext_block
        else:
            unpadded_plaintext = rec_plaintext_block[:-padding_length]
            return unpadded_plaintext












