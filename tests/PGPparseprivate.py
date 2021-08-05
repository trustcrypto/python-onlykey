#!/usr/bin/python
import os
import sys
import pgpy
from Crypto.Util.number import long_to_bytes

#rootkey_passphrase = "example rootkey passphrase"
rootkey_passphrase = "G2SaK_v[ST_hS,-z"
subkey_passphrase = "example subkey passphrase"

# import from file
(rootkey, _) = pgpy.PGPKey.from_file('./testkey.asc')

# import directly
rootkey_ascii_armor = """\
-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: OpenPGP.js v4.10.4
Comment: https://openpgpjs.org
xYYEXwMeqRYJKwYBBAHaRw8BAQdAbnRYP53m7rXE1huNToWCUbxD22TigANr
0JmMV1oxr6L+CQMIpCs/vDznSZdgW38T03R+34px4fgLxw/tPMWxua+PWGlo
QlAdUZ/+1Kg4PQg05UBNieOAWcL+Dk98ajznFIigPaqLtpQAbwlZ4AaKUD/e
Gs0vY3JwdGVzdEBwcm90b25tYWlsLmNvbSA8Y3JwdGVzdEBwcm90b25tYWls
LmNvbT7CeAQQFgoAIAUCXwMeqQYLCQcIAwIEFQgKAgQWAgEAAhkBAhsDAh4B
AAoJEGJPfHwjnCZ1J6wBAM6imkIVk/pwRqGCVHR8OKPotdSUGlZniNxdsKPg
ri1gAQC8BIQEPQceH+/svleU8sgR33QZiWc8o495axXWR0byBMeLBF8DHqkS
CisGAQQBl1UBBQEBB0DqFr4CpAyaeQPb0OeRpKXIQetRHm2Lr6wbHQ0KDFat
cQMBCAf+CQMIBurDBA5ch6Bg3kkKL7nPuc/C39UtQAzyPD0qAtd32hZLJ9xj
4qTac/apasl9D1dG+7P5BOH0CSL2j4N02CHruBs6B+Y8lWL6ROqyWrOBh8Jh
BBgWCAAJBQJfAx6pAhsMAAoJEGJPfHwjnCZ1NLkA/iMBaMud8CiRRLo1z672
hmWZGTbw4uecHx/DGSGN99v4AQCOPrKyVzyu0IPbVcrBXBzKG1mtnKr8opVH
tZtm/3pFBQ==
=exlY
-----END PGP PRIVATE KEY BLOCK-----
"""

(rootkey, _) = pgpy.PGPKey.from_blob(rootkey_ascii_armor)

assert rootkey.is_protected
assert rootkey.is_unlocked is False

try:
    with rootkey.unlock(rootkey_passphrase):
        # rootkey is now unlocked
        assert rootkey.is_unlocked
        print('rootkey is now unlocked')
        primary_key = long_to_bytes(rootkey._key.keymaterial.s)
        print('rootkey value:')
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
                sub_key = long_to_bytes(value._key.keymaterial.s)
                print('subkey value')
                print("".join(["%02x" % c for c in sub_key]))
            # subkey is no longer unlocked
            assert value.is_unlocked is False
            
    except:
        print('Unlocking failed')

# rootkey is no longer unlocked
assert rootkey.is_unlocked is False
