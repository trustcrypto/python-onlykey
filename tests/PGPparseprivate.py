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
=58XF
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

