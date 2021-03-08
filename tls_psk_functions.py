#!/usr/bin/env python

'''
tls_psk_functions.py:
A series of functions implementing aspects of TLS 1.3 PSK functionality
'''

from Crypto.Cipher import AES, ChaCha20_Poly1305
from Crypto.Hash import HMAC, SHA256, SHA384
from Crypto.Random import get_random_bytes
import tls_crypto
import tls_constants
from tls_error import *
import tls_extensions

PSK_KE_MODE = 0
PSK_DHE_KE_MODE = 1
PRESHARED_KEY_TYPE = 41
EARLY_DATA_TYPE = 42
PRESHARED_KEY_TYPE = 45

class DecryptError(Error):
    pass

class PSKFunctions:
    "This is the class for aspects of the handshake protocol"

    def __init__(self, csuites, extensions, psks, role):
        self.csuites = csuites
        self.extensions = extensions
        self.state = tls_constants.INIT_STATE
        self.role = role
        self.neg_group = None
        self.neg_version = None
        self.remote_hs_traffic_secret = None
        self.local_hs_traffic_secret = None
        self.transcript = "".encode()
        self.psks = PSKFunctions
        self.csuite = None


    def attach_handshake_header(self, msg_type, msg):
        len_msg = len(msg).to_bytes(3, 'big')
        hs_msg_type = msg_type.to_bytes(1, 'big')
        return hs_msg_type + len_msg + msg


    def process_handshake_header(self, msg_type, msg):
        curr_pos = 0
        curr_msg_type = msg[curr_pos]
        if (curr_msg_type != msg_type):
            raise InvalidMessageStructureError
        curr_pos = curr_pos + tls_constants.MSG_TYPE_LEN
        msg_len = int.from_bytes(msg[curr_pos:curr_pos + tls_constants.MSG_LEN_LEN], 'big')
        curr_pos = curr_pos + tls_constants.MSG_LEN_LEN
        ptxt_msg = msg[curr_pos:]
        if (msg_len != len(ptxt_msg)):
            raise InvalidMessageStructureError
        return ptxt_msg

    def tls_13_server_new_session_ticket(self, server_static_enc_key, resumption_secret):
        ticket_lifetime =604800
        ticket_lifetime_bytes = ticket_lifetime.to_bytes(4,'big')
        ticket_add_age = get_random_bytes(4)
        ticket_nonce_len = (8).to_bytes(1, 'big')
        ticket_nonce = get_random_bytes(8)
        nonce = get_random_bytes(8)

        our_HDKF = tls_crypto.HKDF(csuite=self.csuite)
        hash_len = our_HDKF.hash_length
        resumption_label = tls_crypto.tls_hkdf_label(label='resumption'.encode(), context=ticket_nonce, length=hash_len)
        PKS = our_HDKF.tls_hkdf_expand(secret=resumption_secret, info=resumption_label, length=hash_len)
        ptxt = PKS + ticket_add_age + ticket_lifetime_bytes + self.csuite.to_bytes(tls_constants.CSUITE_LEN,'big')

        cipher = ChaCha20_Poly1305.new(key=server_static_enc_key, nonce=nonce)
        ciphertext, mac_tag = cipher.encrypt_and_digest(ptxt)
        max_early_data_size = (2**12).to_bytes(4,'big')
        ex_len = len(max_early_data_size).to_bytes(2,'big')
        ticket = nonce + ciphertext + mac_tag
        ticket_len = len(ticket).to_bytes(2, 'big')
        msg = ticket_lifetime_bytes + ticket_add_age + ticket_nonce_len + ticket_nonce + ticket_len + ticket + ex_len + (tls_constants.EARLY_DATA_TYPE).to_bytes(1,'big') + max_early_data_size
        new_session_ticket_msg = PSKFunctions.attach_handshake_header(self, msg_type=tls_constants.NEWST_TYPE, msg=msg)
        return new_session_ticket_msg


    def tls_13_client_parse_new_session_ticket(self, resumption_secret, nst_msg):
        ticketmsg = PSKFunctions.process_handshake_header(self, msg_type=tls_constants.NEWST_TYPE, msg=nst_msg)
        curr_pos = 0
        ticket_lifetime = int.from_bytes(ticketmsg[curr_pos:curr_pos + 4],'big')
        curr_pos = curr_pos + 4
        ticket_add_age = int.from_bytes(ticketmsg[curr_pos:curr_pos + 4],'big')
        curr_pos = curr_pos + 4
        ticket_nonce_len = int.from_bytes(ticketmsg[curr_pos : curr_pos + 1],'big')
        curr_pos = curr_pos + 1
        ticket_nonce = ticketmsg[curr_pos: curr_pos + ticket_nonce_len]
        curr_pos = curr_pos + ticket_nonce_len
        ticket_len = int.from_bytes(ticketmsg[curr_pos : curr_pos + 2],'big')
        curr_pos = curr_pos + 2
        ticket = ticketmsg[curr_pos : curr_pos + ticket_len]

        #outside of the ticket
        curr_pos = curr_pos + ticket_len + 3
        #we are skipping the ext_type + lenght encoding
        max_len = int.from_bytes(ticketmsg[curr_pos:], 'big')


        #Getting the PSK
        our_HDKF = tls_crypto.HKDF(csuite=self.csuite)
        hash_len = our_HDKF.hash_length
        resumption_label = tls_crypto.tls_hkdf_label(label='resumption'.encode(), context=ticket_nonce, length=hash_len)
        PSK = our_HDKF.tls_hkdf_expand(secret=resumption_secret, info=resumption_label, length=hash_len)

        early_secret = tls_crypto.tls_extract_secret(self.csuite, keying_material=PSK, salt= (0).to_bytes(1, 'big'))
        binder_key = tls_crypto.tls_derive_secret(self.csuite, early_secret, "res binder".encode(), "".encode())


        PSK_DICT = {'PSK': PSK, 'lifetime':ticket_lifetime, 'lifetime_add': ticket_add_age,
                    'ticket':ticket, "max_data": max_len, 'binder key': binder_key, 'csuite':self.csuite}
        return PSK_DICT


    def tls_13_client_prep_psk_mode_extension(self, modes):
        ext_type = tls_constants.PSK_KEX_MODE_TYPE.to_bytes(2,'big')
        exmodes = "".encode()
        for exmode in modes:
            exmodes = exmodes + exmode.to_bytes(1,'big')
        exmodeslen = len(exmodes).to_bytes(1,'big')
        PskKeyExchangeModes = ext_type + exmodeslen + exmodes
        return PskKeyExchangeModes

    def tls_13_client_prep_psk_extension(self, PSKS, ticket_age, transcript):
        ticket_age_secs = [age/1000 for age in ticket_age]
        PskIdentities = "".encode()
        binder_len = 0
        for i in range(len(PSKS)):
            PSK = PSKS[i]
            if PSK['lifetime'] >= ticket_age_secs[i]:
                ticket = PSK['ticket']
                ticket_len = len(ticket).to_bytes(2,'big')
                obfuscated_ticket_age = (ticket_age[i] + PSK['lifetime_add']) % 2**32
                PskIdentity = ticket_len + ticket + obfuscated_ticket_age.to_bytes(4,'big')
                PskIdentities = PskIdentities + PskIdentity
                if PSK['csuite'] in [tls_constants.TLS_AES_128_GCM_SHA256, tls_constants.TLS_CHACHA20_POLY1305_SHA256]:
                    hash = SHA256.new()
                else: #if (self.csuite == tls_constants.TLS_AES_256_GCM_SHA384):
                    hash = SHA384.new()


                binder_len = binder_len + hash.digest_size + 1
        len_ids = len(PskIdentities).to_bytes(2, 'big')
        PskIdentities = len_ids + PskIdentities
        ex_type = tls_constants.PSK_TYPE.to_bytes(2,'big')
        ex_len = (binder_len + len(PskIdentities) + 2).to_bytes(2,'big')
        transcript_p = transcript + ex_type + ex_len + PskIdentities
        transcript_hash = tls_crypto.tls_transcript_hash(self.csuite, transcript_p)

        binder_list = "".encode()

        for i in range(len(PSKS)):
            PSK = PSKS[i]
            if PSK['lifetime'] >= ticket_age_secs[i]:
                binder_key = PSK['binder key']
                binder = tls_crypto.tls_finished_mac(csuite=PSK['csuite'], key=binder_key, context=transcript_hash)
                binder_list = binder_list + len(binder).to_bytes(1, 'big') + binder
        binder_list_len = len(binder_list).to_bytes(2,'big')
        binder_list = binder_list_len + binder_list
        OfferedPSK = PskIdentities + binder_list
        extension_data = ex_type + ex_len + OfferedPSK
        return extension_data




    def tls_13_server_parse_psk_extension(self, server_static_enc_key, psk_extension, transcript):
        curr_pos = 0
        ex_type = psk_extension[curr_pos:curr_pos + 2]
        curr_pos = curr_pos + 2
        ex_len = psk_extension[curr_pos: curr_pos + 2]
        curr_pos = curr_pos + 2
        OfferedPSK = psk_extension[curr_pos:]
        curr_pos_O = 0
        len_pskidentities = int.from_bytes(OfferedPSK[curr_pos_O: curr_pos_O + 2], 'big')
        curr_pos_O = curr_pos_O + 2
        psk_identities = OfferedPSK[curr_pos_O: curr_pos_O + len_pskidentities]

        curr_pos_O = curr_pos_O + len_pskidentities
        binder_list_len = int.from_bytes(OfferedPSK[curr_pos_O: curr_pos_O + 2],'big')
        curr_pos_O = curr_pos_O + 2
        binder_list = OfferedPSK[curr_pos_O : curr_pos_O + binder_list_len]

        #COMPUTING THE TRANSCRIPT AND THE TRANSCRIPT HASH

        transcript_p = transcript + ex_type + ex_len + len_pskidentities.to_bytes(2,'big') + psk_identities
        transcript_hash = tls_crypto.tls_transcript_hash(self.csuite, transcript_p)


        #create a dictionary with all of these values saved
        dict_list = []

        pos = 0
        while pos < len_pskidentities:
            ticket_len = int.from_bytes(psk_identities[pos:pos+2], 'big')
            pos = pos + 2
            ticket = psk_identities[pos: pos + ticket_len]
            pos = pos + ticket_len
            obfuscated_ticket_age = int.from_bytes(psk_identities[pos: pos + 4], 'big')
            pos = pos + 4
            #working on the ticket now

            nonce = ticket[:8]
            # note that the mac_tag always has length 16
            ctxt = ticket[8:-16]
            mac_tag = ticket[-16:]
            cipher = ChaCha20_Poly1305.new(key=server_static_enc_key, nonce=nonce)
            ptxt = cipher.decrypt_and_verify(ctxt, mac_tag)
            # ptxt = PKS + ticket_add_age + ticket_lifetime_bytes + self.csuite.to_bytes(tls_constants.CSUITE_LEN,'big')
            len_PSK =  4 + 4 + tls_constants.CSUITE_LEN
            curr_ptxt_pos = 0


            PSK = ptxt[curr_ptxt_pos: -len_PSK]
            curr_txt_pos = -len_PSK
            ticket_add_age = int.from_bytes(ptxt[curr_txt_pos: curr_txt_pos + 4],'big')
            curr_txt_pos = curr_txt_pos + 4
            ticket_lifetime = int.from_bytes(ptxt[curr_txt_pos: curr_txt_pos + 4],'big')
            curr_txt_pos = curr_txt_pos + 4
            csuite = int.from_bytes(ptxt[curr_txt_pos:],'big')




            PSK_DICT = {'PSK': PSK, 'ticket_add_age': ticket_add_age, 'ticket_lifetime':ticket_lifetime,
                        'obfuscated_ticket_age':obfuscated_ticket_age, 'csuite': csuite}

            dict_list.append(PSK_DICT)




        ind = 0
        binder_list_a = []
        while ind < binder_list_len:
            len_binder = binder_list[ind]
            ind = ind + 1
            binder = binder_list[ind: ind + len_binder]
            binder_list_a.append(binder)
            ind = ind + len_binder

        for i in range(len(binder_list_a)):

            psk_id = dict_list[i]
            obfuscated_ticket_age = psk_id['obfuscated_ticket_age']
            ticket_add_age = psk_id['ticket_add_age']
            ticket_lifetime = psk_id['ticket_lifetime']
            csuite = psk_id['csuite']
            PSK = psk_id['PSK']
            age = (obfuscated_ticket_age - ticket_add_age) % 2**32

            if (csuite == self.csuite) and (age <= ticket_lifetime*1000):
                early_secret = tls_crypto.tls_extract_secret(self.csuite, PSK, None)
                binder_key = tls_crypto.tls_derive_secret(csuite=self.csuite, secret=early_secret, label="res binder".encode(), messages="".encode())
                binder = tls_crypto.tls_finished_mac(csuite=self.csuite, key=binder_key, context=transcript_hash)
                if (binder_list_a[i] == binder):
                    return(PSK,i)

        raise DecryptError()







    def tls_13_psk_key_schedule(self, psk_secret, dhe_secret, transcript_one, transcript_two, transcript_three, transcript_four):
        early_secret = tls_crypto.tls_extract_secret(csuite=self.csuite, keying_material=psk_secret, salt=None)
        binder_key = tls_crypto.tls_derive_secret(csuite=self.csuite, secret=early_secret, label="res binder".encode(), messages="".encode())
        client_early_traffic_secret = tls_crypto.tls_derive_secret(csuite=self.csuite, secret=early_secret, label="c e traffic".encode(), messages=transcript_one)
        client_early_key, client_early_iv = tls_crypto.tls_derive_key_iv(csuite=self.csuite, secret=client_early_traffic_secret)
        early_exported_master_secret = tls_crypto.tls_derive_secret(csuite=self.csuite, secret=early_secret, label="e exp master".encode(), messages=transcript_one)
        derived_early_secret = tls_crypto.tls_derive_secret(csuite=self.csuite, secret=early_secret, label="derived".encode(), messages="".encode())
        handshake_secret = tls_crypto.tls_extract_secret(csuite=self.csuite, keying_material=dhe_secret, salt=derived_early_secret)
        client_handshake_traffic_secret = tls_crypto.tls_derive_secret(csuite=self.csuite, secret=handshake_secret, label="c hs traffic".encode(), messages=transcript_two)


        client_handshake_key, client_handshake_iv = tls_crypto.tls_derive_key_iv(csuite=self.csuite, secret=client_handshake_traffic_secret)
        server_handshake_traffic_secret = tls_crypto.tls_derive_secret(csuite=self.csuite,  secret=handshake_secret, label="s hs traffic".encode(), messages=transcript_two)
        server_handshake_key, server_handshake_iv = tls_crypto.tls_derive_key_iv(csuite=self.csuite, secret=server_handshake_traffic_secret)
        derived_handshake_secret = tls_crypto.tls_derive_secret(csuite=self.csuite, secret=handshake_secret, label="derived".encode(), messages="".encode())
        ###
        master_secret = tls_crypto.tls_extract_secret(csuite=self.csuite, keying_material=None, salt=derived_handshake_secret)
        client_application_traffic_secret = tls_crypto.tls_derive_secret(csuite=self.csuite, secret=master_secret, label="c ap traffic".encode(), messages=transcript_three)
        client_application_key, client_application_iv = tls_crypto.tls_derive_key_iv(csuite=self.csuite, secret=client_application_traffic_secret)
        ###
        server_application_traffic_secret = tls_crypto.tls_derive_secret(csuite=self.csuite, secret=master_secret, label="s ap traffic".encode(), messages=transcript_three)
        server_application_key, server_application_iv = tls_crypto.tls_derive_key_iv(csuite=self.csuite, secret=server_application_traffic_secret)
        exporter_master_secret = tls_crypto.tls_derive_secret(csuite=self.csuite, secret=master_secret, label="exp master".encode(), messages=transcript_three)
        resumption_master_secret = tls_crypto.tls_derive_secret(csuite=self.csuite, secret=master_secret, label="res master".encode(), messages=transcript_four)

        return early_secret, binder_key, client_early_traffic_secret, client_early_key, client_early_iv, early_exported_master_secret,\
        derived_early_secret, handshake_secret, client_handshake_traffic_secret, client_handshake_key, client_handshake_iv,\
        server_handshake_traffic_secret, server_handshake_key, server_handshake_iv, derived_handshake_secret, master_secret, \
        client_application_traffic_secret, client_application_key, client_application_iv, server_application_traffic_secret, \
        server_application_key, server_application_iv, exporter_master_secret,resumption_master_secret





