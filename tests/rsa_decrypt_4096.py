# coding: utf-8
import hashlib
import time
import os

from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA
from Crypto.Random import get_random_bytes
from Crypto import Random
import binascii

from onlykey import OnlyKey, Message

print
'Generating a new rsa key pair...'
random_generator = Random.new().read
key = RSA.generate(4096, random_generator)  # generate pub and priv key

p = key.p
q = key.q
n = key.n

binPrivKey = key.exportKey('DER')
binPubKey = key.publickey().exportKey('DER')

print
'Done'
print
print
'RSA p value =', repr(p)
print
'RSA q value =', repr(q)
print
'RSA n value =', repr(n)
print
print
'Initialize OnlyKey client...'
ok = OnlyKey()
print
'Done'
print

time.sleep(2)

ok.read_string(timeout_ms=100)
empty = 'a'
while not empty:
    empty = ok.read_string(timeout_ms=100)

print
'You should see your OnlyKey blink 3 times'
print

print
'Setting RSA private...'


def pack_long(n):
    """this conert 10045587143827198209824131064458461027107542643158086193488942239589004873324146472911535357118684101051965945865943581473431374244810144984918148150975257L
    to "\xbf\xcd\xce\xa0K\x93\x85}\xf0\x18\xb3\xd3L}\x14\xdb\xce0\x00uE,\x05'\xeeW\x1c\xeb\xcf\x8b\x1f\xcc\xc5\xc1\xe2\x17\xb7\xa3\xb6C\x16\xea?\xcchz\xebF1\xb7\xb1\x86\xb8\n}\x82\xebx\xce\x1b\x13\xdf\xdb\x19"
    it seems to be want you wanted? it's 64 bytes.
    """
    h = '%x' % n
    s = ('0' * (len(h) % 2) + h).decode('hex')
    return s


def bin2hex(binStr):
    return binascii.hexlify(binStr)


def hex2bin(hexStr):
    return binascii.unhexlify(hexStr)


hexPrivKey = bin2hex(binPrivKey)
hexPubKey = bin2hex(binPubKey)

# p and q are long ints that are no more than 1/2 the size of pubkey
# I need to convert these into a single byte array put p in the first
# half byte[0] of the byte array and q in the second half byte[(type*128) / 2]
# send the byte array to OnlyKey splitting into 56 bytes per packet
q_and_p = pack_long(q) + pack_long(p)
public_n = pack_long(n)
#
ok.send_large_message3(msg=Message.OKSETPRIV, slot_id=1, key_type=(4 + 32), payload=q_and_p)

# ok.set_rsa_key(1, (1+64), byte array here) #Can only send 56 bytes per packet
# Slot 1 - 4 for RSA
# Type 1 = 1024, Type 2 = 2048, Type 3 = 3072, Type 4 = 4096
# Key Features -
# if backup key = type + 128
# if signature key = type + 64
# if decryption key = type + 32
# if authentication key = type + 16
# For this example it will be a decryption key
time.sleep(1.5)
print
ok.read_string()

time.sleep(2)
print
'You should see your OnlyKey blink 3 times'
print

print
'Trying to read the public RSA N part 1...'
ok.send_message(msg=Message.OKGETPUBKEY, payload=chr(1))  # , payload=[1, 1])
time.sleep(1.5)
for _ in xrange(10):
    ok_pubkey1 = ok.read_bytes(64, to_str=True, timeout_ms=1000)
    if len(ok_pubkey1) == 64:
        break
    time.sleep(1)

print

print
'received=', repr(ok_pubkey1)

print
'Trying to read the public RSA N part 2...'
for _ in xrange(10):
    ok_pubkey2 = ok.read_bytes(64, to_str=True, timeout_ms=1000)
    if len(ok_pubkey2) == 64:
        break
    time.sleep(1)

print

print
'received=', repr(ok_pubkey2)

print
'Trying to read the public RSA N part 3...'
for _ in xrange(10):
    ok_pubkey3 = ok.read_bytes(64, to_str=True, timeout_ms=1000)
    if len(ok_pubkey3) == 64:
        break
    time.sleep(1)

print

print
'received=', repr(ok_pubkey3)

print
'Trying to read the public RSA N part 4...'
for _ in xrange(10):
    ok_pubkey4 = ok.read_bytes(64, to_str=True, timeout_ms=1000)
    if len(ok_pubkey4) == 64:
        break
    time.sleep(1)

print

print
'received=', repr(ok_pubkey4)

print
'Trying to read the public RSA N part 5...'
for _ in xrange(10):
    ok_pubkey5 = ok.read_bytes(64, to_str=True, timeout_ms=1000)
    if len(ok_pubkey5) == 64:
        break
    time.sleep(1)

print

print
'received=', repr(ok_pubkey5)

print
'Trying to read the public RSA N part 6...'
for _ in xrange(10):
    ok_pubkey6 = ok.read_bytes(64, to_str=True, timeout_ms=1000)
    if len(ok_pubkey6) == 64:
        break
    time.sleep(1)

print

print
'received=', repr(ok_pubkey6)

print
'Trying to read the public RSA N part 7...'
for _ in xrange(10):
    ok_pubkey7 = ok.read_bytes(64, to_str=True, timeout_ms=1000)
    if len(ok_pubkey7) == 64:
        break
    time.sleep(1)

print

print
'received=', repr(ok_pubkey7)

print
'Trying to read the public RSA N part 8...'
for _ in xrange(10):
    ok_pubkey8 = ok.read_bytes(64, to_str=True, timeout_ms=1000)
    if len(ok_pubkey8) == 64:
        break
    time.sleep(1)

print

print
'received=', repr(ok_pubkey8)

if not ok_pubkey8:
    raise Exception('failed to set the RSA key')

print
'Assert that the received public N match the one generated locally'
print
'Local Public N=', repr(public_n)
ok_pubkey = ok_pubkey1 + ok_pubkey2 + ok_pubkey3 + ok_pubkey4 + ok_pubkey5 + ok_pubkey6 + ok_pubkey7 + ok_pubkey8
assert ok_pubkey == public_n
print
'Ok, public N matches'
print

message = 'Secret message'
# h = SHA.new(message)
cipher = PKCS1_v1_5.new(key)
ciphertext = cipher.encrypt(message)

# hex_enc_data = bin2hex(enc_data)
print
'encrypted payload = ', repr(ciphertext)
print

# Compute the challenge pin
h = hashlib.sha256()
h.update(ciphertext)
d = h.digest()

assert len(d) == 32


def get_button(byte):
    ibyte = ord(byte)
    if ibyte < 6:
        return 1
    return ibyte % 5 + 1


b1, b2, b3 = get_button(d[0]), get_button(d[15]), get_button(d[31])

print
'Sending the payload to the OnlyKey...'
ok.send_large_message2(msg=Message.OKDECRYPT, payload=ciphertext, slot_id=1)

print
'Please enter the 3 digit challenge code on OnlyKey (and press ENTER if necessary)'
print
'{} {} {}'.format(b1, b2, b3)
raw_input()
print
'Trying to read the decrypted data from OnlyKey...'
ok_decrypted = ''
while ok_decrypted == '':
    time.sleep(0.5)
    ok_decrypted = ok.read_bytes(len(message), to_str=True)

dsize = len(message)
sentinel = Random.new().read(15 + dsize)
plaintext = cipher.decrypt(ciphertext, sentinel)

print
'Decrypted by OnlyKey, data=', repr(ok_decrypted)

print
'Local decrypted data =', repr(plaintext)
print
'Assert that the decrypted data generated locally matches the data generated on the OnlyKey'
assert repr(ok_decrypted) == repr(plaintext)
print
'Ok, data matches'
print

print
'Done'
