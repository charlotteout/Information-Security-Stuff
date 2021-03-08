#Lab 1 Applied cryptography

import base64
import tempfile

#Exercise 1
#Convert the following ASCII string into its hexadecimal representation
string = "Karma police, arrest this man, he talks math"
enc_string = string.encode('utf-8')
hex_string = enc_string.hex()

#XOR the string byte-wise with 0x01
xor_string = "".join([chr(ord(char)^0x01) for char in string])

#Encode the resulting string to base64
b64_string = base64.b64encode(xor_string.encode('utf-8'))

file = tempfile.TemporaryFile()
file.write(b64_string)
file.close()

#Exercise 2
#The hex encoded string below has been produced by XORing a message byte-wise
#with a single character. Find the key and decrypt the message

#the idea of this exercise is to try with trial and error all possible keys
#then we observe the ciphertext manually and see what results in an sentence
#in english language

def trial_decrypt():
    enc_string = "210e09060b0b1e4b4714080a02080902470b0213470a0247081213470801470a1e4704060002"
    decode_string = bytes.fromhex(enc_string).decode('utf-8')
    for integer in range(127):
        xorstring = ""
        for char in decode_string:
            xorstring = xorstring + chr((ord(char)) ^ integer)
        print("integer", integer)
        print("xorstring", xorstring)

trial_decrypt()
#the correct one is: 103,g, resulting in the sentence
#"Finally, someone let me out of my cage"

#Exercise 3
#Define a function that will take an arbitrary-sized string that you wish
#to encrypt, and output a one-time pad encrypted ciphertext

import os

def xor_string(bytes_one, bytes_two):
    xor_set = []
    for i in range(len(bytes_one)):
        xor_value = chr(ord(bytes_one[i])^ bytes_two[i])
        xor_set.append(xor_value)
    string = "".join(xor_set)
    return string

def onetimepadencryption(pt_string):
    onetimepad = os.urandom(len(pt_string))
    ciph_string = xor_string(pt_string, onetimepad)
    return ciph_string, onetimepad

def ontimepaddecryption(ciph_string, onetimepad):
    ptxt_string = xor_string(ciph_string,onetimepad)
    return ptxt_string























