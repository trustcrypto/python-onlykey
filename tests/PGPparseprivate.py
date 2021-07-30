#!/usr/bin/python
import os
import sys
import pgpy
from Crypto.Util.number import long_to_bytes

privkey_passphrase = "G2SaK_v[ST_hS,-z"
privkey_ascii_armor = """\
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

(privkey, _) = pgpy.PGPKey.from_blob(privkey_ascii_armor)

assert privkey.is_protected
assert privkey.is_unlocked is False

try:
    with privkey.unlock(privkey_passphrase):
        # privkey is now unlocked
        assert privkey.is_unlocked
        print('privkey is now unlocked')
        primary_key = long_to_bytes(privkey._key.keymaterial.s)
        print('privkey key value:')
        print("".join(["%02x" % c for c in primary_key]))
        print('subkey key values:')
        for key, value in privkey._children.items():
            print('subkey id', key)
            sub_key = long_to_bytes(value._key.keymaterial.s)
            print('subkey key value')
            print("".join(["%02x" % c for c in sub_key]))
        
except: 
    print('Unlocking failed')

# privkey is no longer unlocked
assert privkey.is_unlocked is False