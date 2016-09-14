# coding: utf-8
import time
import os

import ed25519

from onlykey import OnlyKey, Message

print 'Generating a new ed25519 key pair...'
privkey, pubkey = ed25519.create_keypair(entropy=os.urandom)
print 'Done'
print

print 'privkey=', repr(privkey.to_seed())
print 'privkey hex=', ''.join([c.encode('hex') for c in privkey.to_seed()])
print 'pubkey=', repr(pubkey.to_bytes())
print 'pubkey hex=', pubkey.to_ascii(encoding='hex')
print

print
print 'Initialize OnlyKey client...'
ok = OnlyKey()
print 'Done'
print

time.sleep(2)
print 'You should see your OnlyKey blink 3 times'
print

ok.read_string(timeout_ms=100)
empty = 'a'
while not empty:
    empty = ok.read_string(timeout_ms=100)

print 'Setting SSH private...'
ok.send_message(msg=Message.OKSETSSHPRIV, payload=privkey.to_seed())
time.sleep(0.5)
print ok.read_string()

time.sleep(2)
print 'You should see your OnlyKey blink 3 times'
print

print 'Trying to read the pubkey...'
ok.send_message(msg=Message.OKGETSSHPUBKEY)
time.sleep(0.5)
for _ in xrange(10):
    ok_pubkey = ok.read_bytes(32, to_str=True)
    if ok_pubkey:
        break
    time.sleep(0.5)

print

if not ok_pubkey:
    raise Exception('failed to set the SSH key')

print 'Assert that the received pubkey match the one generated locally'
assert ok_pubkey == pubkey.to_bytes()
print 'Ok'
print

test_payload = os.urandom(150)
print 'test_payload=', repr(test_payload)
print

print 'Sending the payload to the OnlyKey...'
ok.send_large_message(msg=Message.OKSIGNSSHCHALLENGE, payload=test_payload)
print 'Please touch a button (and press ENTER if necessary)'
raw_input()
time.sleep(0.2)
ok.send_large_message(msg=Message.OKSIGNSSHCHALLENGE, payload=test_payload)
signature = ''
while signature == '':
    time.sleep(0.5)
    signature = ok.read_bytes(64, to_str=True)

print 'Signed, signature=', repr(signature)

print 'Local signature=', repr(privkey.sign(bytes(test_payload)))
print 'Assert that the signature generated locally match the one generated on the OnlyKey'
assert repr(signature) == repr(privkey.sign(bytes(test_payload)))
print 'Ok'
print

print 'Done'
