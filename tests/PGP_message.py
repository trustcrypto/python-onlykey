#!/usr/bin/env python
import hashlib
import time
import os
import sys

# from progressbar import ProgressBar, AnimatedMarker, Timer, Bar, Percentage, Widget

import pgpy
from pgpy import PGPKey
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm, ok
from pgpy.packet.fields import RSAPub, MPI, RSAPriv
from pgpy.packet.packets import PubKeyV4, PrivKeyV4

from datetime import timedelta

import binascii

from onlykey import OnlyKey, Message


def custRSAPub(n, e):
    res = RSAPriv()
    res.n = MPI(n)
    res.e = MPI(e)
    return res


def custPubKeyV4(custkey):
    res = PrivKeyV4()
    res.pkalg = PubKeyAlgorithm.RSAEncryptOrSign
    res.keymaterial = custkey
    res.update_hlen()
    return res


def rsatogpg(e, N, name, **idargs):
    """
    :param e,N: RSA parameters as Python integers or longints
    :param name: Identity name
    :param idargs: PGP Identity parameters, such as comment,email
    :return: PGPy pubkey object
    """
    rsakey = custPubKeyV4(custRSAPub(N, e))
    pgpkey = pgpy.PGPKey()
    pgpkey._key = rsakey

    uid = pgpy.PGPUID.new(name, **idargs)
    uid._parent = pgpkey
    pgpkey._uids.append(uid)
    return pgpkey


def makekey():
    n = ok.getpub()
    if len(n) == 128:
        priv_key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 1024)
    if len(n) == 256:
        priv_key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
    if len(n) == 384:
        priv_key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 3072)
    if len(n) == 512:
        priv_key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)
    # uid = pgpy.PGPUID.new('Abraham Lincoln', comment='Honest Abe', email='abraham.lincoln@whitehouse.gov')
    # priv_key.add_uid(uid, usage={KeyFlags.Sign}, hashes=[HashAlgorithm.SHA512, HashAlgorithm.SHA256],
    #        compression=[CompressionAlgorithm.BZ2, CompressionAlgorithm.Uncompressed],
    #        key_expires=timedelta(days=365))
    # p = n[:(len(n)/2)]
    # q = n[(len(n)/2):]
    n = n.encode("HEX")
    N = long(n, 16)
    # p = p.encode("HEX")
    # p = long(p, 16)
    # q = q.encode("HEX")
    # q = long(q, 16)
    e = int('10001', 16)
    # pub = rsatogpg(e,N,p,q,'Nikola Tesla')
    # rsakey = custPubKeyV4(custRSAPub(N,e))
    # priv_key._key = rsakey
    return priv_key


# we can start by generating a primary key. For this example, we'll use RSA, but it could be DSA or ECDSA as well
# with open('test_priv.asc', 'rb') as f:
#    t = f.read().replace('\r', '')

# priv_key, _ = PGPKey.from_blob(t)
priv_key = pgpy.PGPKey()
# we now have some key material, but our new key doesn't have a user ID yet, and therefore is not yet usable!
# with priv_key.unlock("test"):
#    uid = pgpy.PGPUID.new('Abraham Lincoln', comment='Honest Abe', email='abraham.lincoln@whitehouse.gov')
# now we must add the new user id to the key. We'll need to specify all of our preferences at this point
# because PGPy doesn't have any built-in key preference defaults at this time
# this example is similar to GnuPG 2.1.x defaults, with no expiration or preferred keyserver
# priv_key.add_uid(uid, usage={KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
#             hashes=[HashAlgorithm.SHA256, HashAlgorithm.SHA384, HashAlgorithm.SHA512, HashAlgorithm.SHA224],
#             ciphers=[SymmetricKeyAlgorithm.AES256, SymmetricKeyAlgorithm.AES192, SymmetricKeyAlgorithm.AES128],
#             compression=[CompressionAlgorithm.ZLIB, CompressionAlgorithm.BZ2, CompressionAlgorithm.ZIP, CompressionAlgorithm.Uncompressed])

print
print
'Do you want to sign or decrypt a message?'
print
's = sign, d = decrypt'
print

action = raw_input()

print
print
'Enter RSA key slot number to use (1 - 4) or enter 0 to list key labels'
print

slot = int(raw_input())
ok.slot(slot)

while slot == 0:
    ok.displaykeylabels()
    print
    print
    'Enter slot number to use (1 - 4) or enter 0 to list key labels'
    print
    slot = int(raw_input())
    ok.slot(slot)

# PGPMessage will automatically determine if this is a cleartext message or not
# message_from_file = pgpy.PGPMessage.from_file("path/to/a/message")
if action == 's':
    priv_key = makekey()
    uid = pgpy.PGPUID.new('Nikola Tesla')
    # uid._parent = priv_key
    priv_key.add_uid(uid, usage={KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
                     hashes=[HashAlgorithm.SHA256, HashAlgorithm.SHA384, HashAlgorithm.SHA512, HashAlgorithm.SHA224],
                     ciphers=[SymmetricKeyAlgorithm.AES256, SymmetricKeyAlgorithm.AES192, SymmetricKeyAlgorithm.AES128],
                     compression=[CompressionAlgorithm.ZLIB, CompressionAlgorithm.BZ2, CompressionAlgorithm.ZIP,
                                  CompressionAlgorithm.Uncompressed],
                     key_expires=timedelta(days=365))

    print
    print
    'Do you want to sign a text message or add signature to a PGP Message?'
    print
    't = text message, p = PGP Message'
    print
    action2 = raw_input()
    if action2 == 't':
        print
        print
        'Type or paste the text message, press return to go to new line, and then press Ctrl+D or Ctrl+Z (Windows only)'
        print
        msg_blob = sys.stdin.read()
        message_from_blob = priv_key.sign2(msg_blob)
        print
        'Encoded Signed Message ='
        print
        '-----BEGIN PGP SIGNED MESSAGE-----'
        print
        'Hash: SHA256'
        print
    if action2 == 'p':
        print
        print
        'Paste OpenPGP Message, press return to go to new line, and then press Ctrl+D or Ctrl+Z (Windows only)'
        print
        msg_blob = sys.stdin.read()
        message_from_blob = pgpy.PGPMessage.from_blob(msg_blob)
        print
        print
        'Message=', repr(message_from_blob)
        message_from_blob |= priv_key.sign2(message_from_blob)
        print
        'Encoded Signed Message ='
    # print
    # sign_bytes = message_from_blob.__bytes__()
    # print 'Message Bytes=', repr(sign_bytes)
    # print
    sign_text = str(message_from_blob)
    print
    msg_blob, sign_text
    print
    # print 'Decoded Signed Message =', str(sign_bytes)
if action == 'd':
    # pub_key = makepub()
    print
    print
    'Paste OpenPGP Message, press return to go to new line, and then press Ctrl+D or Ctrl+Z (Windows only)'
    print
    msg_blob = sys.stdin.read()
    message_from_blob = pgpy.PGPMessage.from_blob(msg_blob)
    print
    print
    'Message=', repr(message_from_blob)
    # with priv_key.unlock("test"):
    decrypted_message = priv_key.decrypt(message_from_blob)
    # decrypted_message2 = priv_key.parse(decrypted_message)
    # decrypted_message3 = priv_key.bytes_to_text(message_from_blob)
    print
    dec_bytes = decrypted_message.__bytes__()
    print
    'Decoded Decrypted Message =', str(dec_bytes)
    print
    dec_text = str(decrypted_message)
    print
    'Encoded Decrypted Message ='
    print
    dec_text

print
'Done'
