# coding: utf-8
import hashlib
import time
import os

import ed25519

from onlykey import OnlyKey, Message

print
'Generating a new ed25519 key pair...'
privkey, pubkey = ed25519.create_keypair(entropy=os.urandom)
print
'Done'
print

print
'privkey=', repr(privkey.to_seed())
print
'privkey hex=', ''.join([c.encode('hex') for c in privkey.to_seed()])
print
'pubkey=', repr(pubkey.to_bytes())
print
'pubkey hex=', pubkey.to_ascii(encoding='hex')
print

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
'Setting SSH private...'
ok.set_ecc_key(101, (1 + 64), privkey.to_seed())
# ok.set_ecc_privsend_message(msg=Message.OKSETPRIV, payload=privkey.to_seed())
time.sleep(1.5)
print
ok.read_string()

time.sleep(2)
print
'You should see your OnlyKey blink 3 times'
print

print
'Trying to read the pubkey...'
ok.send_message(msg=Message.OKGETPUBKEY, payload=chr(101))  # , payload=[1, 1])
time.sleep(1.5)
for _ in xrange(10):
    ok_pubkey = ok.read_bytes(32, to_str=True)
    if len(ok_pubkey) == 32:
        break
    time.sleep(1)

print

print
'received=', repr(ok_pubkey)

if not ok_pubkey:
    raise Exception('failed to set the SSH key')

print
'Assert that the received pubkey match the one generated locally'
assert ok_pubkey == pubkey.to_bytes()
print
'Ok, pubkey matches'
print

test_payload = os.urandom(150)
print
'test_payload=', repr(test_payload)
print

# Compute the challenge pin
h = hashlib.sha256()
h.update(test_payload)
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
ok.send_large_message2(msg=Message.OKSIGNCHALLENGE, payload=test_payload, slot_id=101)

# Tim - The OnlyKey can send the code to enter but it would be better if the app generates
# the code, this way in order to trick a user into approving an unauthorized signature
# the app, in this case this python code would have to be hacked on the user's system.
# How the OnlyKey creates the three digit code:
# SHA256_CTX CRYPTO;
# sha256_init(&CRYPTO);
# sha256_update(&CRYPTO, large_buffer, large_data_offset); //step 1 create a sha256 hash of
# sha256_final(&CRYPTO, rsa_signature); //the data to sign
# if (rsa_signature[0] < 6) Challenge_button1 = '1'; //step 2 Convert first byte of hash to
# else { //first button to press (remainder of byte is a base 6 number 0 - 5)
# Challenge_button1 = rsa_signature[0] % 5;
# Challenge_button1 = Challenge_button1 + '0' + 1; //Add '0' and 1 so number will be ASCII 1 - 6
# }
# if (rsa_signature[15] < 6) Challenge_button2 = '1'; //step 3 do the same with 16th byte to
# else { // get Challenge_button2
# Challenge_button2 = rsa_signature[15] % 5;
# Challenge_button2 = Challenge_button2 + '0' + 1;
# }
# if (rsa_signature[31] < 6) Challenge_button3 = '1'; //step 4 do the same with 32nd byte to
# else { // get Challenge_button
# Challenge_button3 = rsa_signature[31] % 5;
# Challenge_button3 = Challenge_button3 + '0' + 1;
# }
# step 5 display the code to user to enter on OnlyKey

# This method prevents some malware on a users system from sending fake requests to be signed
# at the same time as real requests and tricking the user into signing the wrong data
print
'Please enter the 3 digit challenge code on OnlyKey (and press ENTER if necessary)'
print
'{} {} {}'.format(b1, b2, b3)
raw_input()
signature = ''
while signature == '':
    time.sleep(0.5)
    signature = ok.read_bytes(64, to_str=True)

print
'Signed by OnlyKey, signature=', repr(signature)

print
'Local signature=', repr(privkey.sign(bytes(test_payload)))
print
'Assert that the signature generated locally match the one generated on the OnlyKey'
assert repr(signature) == repr(privkey.sign(bytes(test_payload)))
print
'Ok, signatures match'
print

print
'Done'
