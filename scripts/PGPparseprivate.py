#!/usr/bin/python
import os
import sys
import pgpy
from Crypto.Util.number import long_to_bytes

# This python script can parse the private keys out of OpenPGP keys (ed25519 or RSA). 
# Replace the passphrase with your OpenPGP passphrase.
rootkey_passphrase = "test"
# If you use a different passphrase for subkeys (such as rootless subkeys) replace 
# the passphrase below with your OpenPGP subkey passphrase
subkey_passphrase = "example subkey passphrase"

# Replace this with your ascii armored OpenPGP key
rootkey_ascii_armor = """\
-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: Mailvelope v4.4.1
Comment: https://www.mailvelope.com

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
tvTu13Yy
=pOOJ
-----END PGP PRIVATE KEY BLOCK-----
"""

(rootkey, _) = pgpy.PGPKey.from_blob(rootkey_ascii_armor)

# Or if you would prefer, import key as a file like this
# (rootkey, _) = pgpy.PGPKey.from_file('./testkey.asc')

# Run the script and raw keys will be displayed. Only run this on a 
# secure trusted system.

assert rootkey.is_protected
assert rootkey.is_unlocked is False

try:
    print('Load these raw key values to OnlyKey by using the OnlyKey App --> Advanced -> Add Private Key')
    with rootkey.unlock(rootkey_passphrase):
        # rootkey is now unlocked
        assert rootkey.is_unlocked
        print('rootkey is now unlocked')
        print('rootkey type %s', rootkey._key._pkalg)
        if 'RSA' in rootkey._key._pkalg._name_:
            print('rootkey value:')
            #Parse rsa pgp key
            primary_keyp = long_to_bytes(rootkey._key.keymaterial.p)
            primary_keyq = long_to_bytes(rootkey._key.keymaterial.q)
            print(("".join(["%02x" % c for c in primary_keyp])) + ("".join(["%02x" % c for c in primary_keyq])))
            print('rootkey size =', (len(primary_keyp)+len(primary_keyq))*8, 'bits')
            print('subkey values:')
            for subkey, value in rootkey._children.items():
                print('subkey id', subkey)
                sub_keyp = long_to_bytes(value._key.keymaterial.p)
                sub_keyq = long_to_bytes(value._key.keymaterial.q)
                print('subkey value')
                print(("".join(["%02x" % c for c in sub_keyp])) + ("".join(["%02x" % c for c in sub_keyq])))
                print('subkey size =', (len(primary_keyp)+len(primary_keyq))*8, 'bits')
        else:
            print('rootkey value:')
            #Parse ed25519 pgp key
            primary_key = long_to_bytes(rootkey._key.keymaterial.s)
            print("".join(["%02x" % c for c in primary_key]))
            print('subkey values:')
            for subkey, value in rootkey._children.items():
                print('subkey id', subkey)
                sub_key = long_to_bytes(value._key.keymaterial.s)
                print('subkey value')
                print("".join(["%02x" % c for c in sub_key]))
        
except:
    print('Unlocking root key failed, attempting rootless subkey unlock.')
    try:
        print('subkey key values:')
        for subkey, value in rootkey._children.items():
            assert value.is_protected
            assert value.is_unlocked is False
            with value.unlock(subkey_passphrase):
                # subkey is now unlocked
                assert value.is_unlocked
                print('subkey is now unlocked')
                print('subkey id', subkey)
                if 'RSA' in subkey._key._pkalg._name_:
                    sub_keyp = long_to_bytes(value._key.keymaterial.p)
                    sub_keyq = long_to_bytes(value._key.keymaterial.q)
                    print('subkey value')
                    print(("".join(["%02x" % c for c in sub_keyp])) + ("".join(["%02x" % c for c in sub_keyq])))
                else:
                    sub_key = long_to_bytes(value._key.keymaterial.s)
                    print('subkey value')
                    print("".join(["%02x" % c for c in sub_key]))
            # subkey is no longer unlocked
            assert value.is_unlocked is False
            
    except:
        print('Unlocking failed')

# rootkey is no longer unlocked
assert rootkey.is_unlocked is False

