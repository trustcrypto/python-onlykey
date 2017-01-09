# coding: utf-8
import hashlib
import time
import os

import rsa

from onlykey import OnlyKey, Message

print 'Generating a new rsa key pair...'
(pubkey, privkey) = rsa.newkeys(2048, poolsize=8)
# privkey, pubkey = rsa.create_keypair(entropy=os.urandom)
# documentation https://stuvel.eu/python-rsa-doc/usage.html#generating-keys


print 'Done'
print

print 'privkey=', repr(privkey)
#print 'privkey hex=', ''.join([c.encode('hex') for c in privkey.to_seed()])
# not displaying correctly
print 'pubkey=', repr(pubkey)
#print 'pubkey hex=', pubkey.to_ascii(encoding='hex')
# not displaying correctly
print

print
print 'Initialize OnlyKey client...'
ok = OnlyKey()
print 'Done'
print

time.sleep(2)

ok.read_string(timeout_ms=100)
empty = 'a'
while not empty:
    empty = ok.read_string(timeout_ms=100)

print 'You should see your OnlyKey blink 3 times'
print

print 'Setting SSH private...'
rsaslot = 1
rsatype = 2
ok.set_ecc_key(rsaslot, rsatype, privkey)
# Slot 1 - 4 for RSA
# Type 1 = 1024, Type 2 = 2048
# ok.set_ecc_privsend_message(msg=Message.OKSETPRIV, payload=privkey.to_seed())
time.sleep(1.5)
print ok.read_string()

time.sleep(2)
print 'You should see your OnlyKey blink 3 times'
print

print 'Trying to read the pubkey...'
ok.send_message(msg=Message.OKGETPUBKEY, payload=chr(101))  #, payload=[1, 1])
time.sleep(1.5)
for _ in xrange(10):
    ok_pubkey = ok.read_bytes((rsatype*128), to_str=True)
    if len(ok_pubkey) == (rsatype*128):
        break
    time.sleep(1)

print

print 'received=', repr(ok_pubkey)

if not ok_pubkey:
    raise Exception('failed to set the SSH key')

print 'Assert that the received pubkey match the one generated locally'
assert ok_pubkey == pubkey.to_bytes()
print 'Ok, pubkey matches'
print

test_payload = os.urandom(150)
print 'test_payload=', repr(test_payload)
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

print 'Sending the payload to the OnlyKey...'
ok.send_large_message2(msg=Message.OKSIGNCHALLENGE, payload=test_payload)

print 'Please enter the 3 digit challenge code on OnlyKey (and press ENTER if necessary)'
print '{} {} {}'.format(b1, b2, b3)
raw_input()
time.sleep(0.2)
ok.send_large_message2(msg=Message.OKSIGNCHALLENGE, payload=test_payload)
signature = ''
while signature == '':
    time.sleep(0.5)
    signature = ok.read_bytes(256, to_str=True)

print 'Signed by OnlyKey, signature=', repr(signature)

print 'Local signature=', repr(rsa.sign(test_payload, privkey, 'SHA-256'))
print 'Assert that the signature generated locally match the one generated on the OnlyKey'
assert repr(signature) == repr(rsa.sign(test_payload, privkey, 'SHA-256'))
print 'Ok, signatures match'
print

print 'Done'
