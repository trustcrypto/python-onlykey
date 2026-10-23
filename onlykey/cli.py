# coding: utf-8
from __future__ import unicode_literals, print_function
from __future__ import absolute_import

from builtins import input
from builtins import next
from builtins import range
import base64
import binascii
import time
import logging
import atexit
import os
import sys
import solo
import solo.operations
from solo.cli.key import key
from solo.cli.monitor import monitor
from solo.cli.program import program

from prompt_toolkit import prompt
from prompt_toolkit import Application
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.keys import Keys
from prompt_toolkit.filters import Condition
import nacl.signing

from .client import OnlyKey, Message, MessageField, WEBCRYPTPOLICY_FIELD


def _cli_version():
    """The installed package version - the one number setup.py declares.

    The CLI used to print a hard-coded 'v1.2.10' in three places while setup.py
    said 1.2.11, so `onlykey-cli version` reported a release that was not the
    one installed. Reading the distribution metadata makes setup.py the only
    place the number lives.
    """
    try:
        from importlib.metadata import version, PackageNotFoundError
    except ImportError:  # pragma: no cover - python_requires is >= 3.10
        return 'unknown'
    try:
        return version('onlykey')
    except PackageNotFoundError:
        return 'unknown (not installed as a package)'


class _LazyOnlyKey(object):
    """Connect on first use, not at import.

    `only_key = OnlyKey()` ran at module import, so EVERY invocation - including
    `onlykey-cli version`, `help` and `-h`, which never talk to a key - opened
    the device first: a key on the bus saw traffic it did not ask for, and a
    missing key made `version` fail. The proxy defers the connection to the
    first attribute a command actually uses, so the commands that need no
    device never touch one.
    """

    def __init__(self):
        object.__setattr__(self, '_ok', None)

    def _get(self):
        ok = object.__getattribute__(self, '_ok')
        if ok is None:
            ok = OnlyKey()
            object.__setattr__(self, '_ok', ok)
        return ok

    def __getattr__(self, name):
        return getattr(self._get(), name)

    def close_if_open(self):
        """Close the HID handle if a command opened one - and never open one to
        close it, which is what the exit handler did through the proxy."""
        ok = object.__getattribute__(self, '_ok')
        if ok is not None:
            ok._hid.close()

    def __setattr__(self, name, value):
        setattr(self._get(), name, value)


only_key = _LazyOnlyKey()


def _pqc_input_bytes(arg):
    """Read a PQC operand given as a hex string or as a path to a file.

    A file is tried as hex text first and taken as raw bytes if that fails, so
    both a `.hex`-style dump and a raw binary file work. Accepting a path
    matters here because an ML-KEM ciphertext is 1088 bytes - 2176 hex
    characters - which is past what several shells will take as one argument.

    This is for CIPHERTEXT and digest operands (signpqc, decryptpqc), which are
    public data. Key material has no equivalent: loadpqc takes an armored key
    file and nothing else.
    """
    if os.path.isfile(arg):
        raw = open(arg, 'rb').read()
        try:
            return bytes.fromhex(raw.decode().strip())
        except Exception:
            return raw
    return bytes.fromhex(arg.strip())


def cli():

    logging.basicConfig(level=logging.DEBUG)

    # Control-T handling
    hidden = [True]  # Nonlocal
    key_bindings = KeyBindings()

    @key_bindings.add('c-t')
    def _(event):
        ' When Control-T has been pressed, toggle visibility. '
        hidden[0] = not hidden[0]

    def prompt_pass():
        print('Type Control-T to toggle password visible.')
        password = prompt('Password/Key: ',
                          is_password=Condition(lambda: hidden[0]),
                          key_bindings=key_bindings)
        return password

    def prompt_key():
        print('Type Control-T to toggle key visible.')
        key = prompt('Key: ',
                     is_password=Condition(lambda: hidden[0]),
                     key_bindings=key_bindings)
        return key

    def prompt_pin():
        print('Press any key when finished entering PIN')
        return

    if len(sys.argv) > 1:
        if sys.argv[1] == 'settime':
            only_key.set_time(time.time())
            print(only_key.read_string())
        elif sys.argv[1] == 'init':
            while 1:
                if only_key.read_string(timeout_ms=500) != 'UNINITIALIZED':
                    break
            for msg in [Message.OKSETPIN]:
                only_key.send_message(msg=msg)
                print(only_key.read_string())
                print ()
                input('Press the Enter key once you are done')
                only_key.send_message(msg=msg)
                print(only_key.read_string())
                only_key.send_message(msg=msg)
                print(only_key.read_string())
                print ()
                input('Press the Enter key once you are done')
                only_key.send_message(msg=msg)
                time.sleep(1.5)
                print(only_key.read_string())
                print ()
            for msg in [Message.OKSETPDPIN]:
                only_key.send_message(msg=msg)
                print(only_key.read_string() + ' for second profile')
                print ()
                input('Press the Enter key once you are done')
                only_key.send_message(msg=msg)
                print(only_key.read_string() + ' for second profile')
                only_key.send_message(msg=msg)
                print(only_key.read_string())
                print ()
                input('Press the Enter key once you are done')
                only_key.send_message(msg=msg)
                time.sleep(1.5)
                print(only_key.read_string())
                print ()
            for msg in [Message.OKSETSDPIN]:
                only_key.send_message(msg=msg)
                print(only_key.read_string())
                print ()
                input('Press the Enter key once you are done')
                only_key.send_message(msg=msg)
                print(only_key.read_string())
                only_key.send_message(msg=msg)
                print(only_key.read_string())
                print ()
                input('Press the Enter key once you are done')
                only_key.send_message(msg=msg)
                time.sleep(1.5)
                print(only_key.read_string())
                print ()
        elif sys.argv[1] == 'getlabels':
            tmp = {}      
            if not only_key.is_duo():
                for slot in only_key.getlabels():
                    tmp[slot.name] = slot
                    slots = iter(['1a', '1b', '2a', '2b', '3a', '3b', '4a', '4b', '5a', '5b', '6a', '6b'])
                for slot_name in slots:
                    print(tmp[slot_name].to_str().replace('ÿ'," "))
                    print(tmp[next(slots)].to_str().replace('ÿ'," "))
                    print()
            else:
                for slot in only_key.getduolabels():
                    tmp[slot.name] = slot
                    slots = iter(['Green 1a', 'Green 2a', 'Green 3a', 'Green 1b', 'Green 2b', 'Green 3b', 'Blue 1a', 'Blue 2a', 'Blue 3a', 'Blue 1b', 'Blue 2b', 'Blue 3b', 'Yellow 1a', 'Yellow 2a', 'Yellow 3a', 'Yellow 1b', 'Yellow 2b', 'Yellow 3b', 'Purple 1a', 'Purple 2a', 'Purple 3a', 'Purple 1b', 'Purple 2b', 'Purple 3b'])
                for slot_name in slots:
                    print(tmp[slot_name].to_str().replace('ÿ'," "))
                    print(tmp[next(slots)].to_str().replace('ÿ'," "))
                    print(tmp[next(slots)].to_str().replace('ÿ'," "))
                    print(tmp[next(slots)].to_str().replace('ÿ'," "))
                    print(tmp[next(slots)].to_str().replace('ÿ'," "))
                    print(tmp[next(slots)].to_str().replace('ÿ'," "))
                    print()
        elif sys.argv[1] == 'getkeylabels':
            tmp = {}
            for slot in only_key.getkeylabels():
                tmp[slot.name] = slot
            slots = iter(['RSA Key 1', 'RSA Key 2', 'RSA Key 3', 'RSA Key 4', 'ECC Key 1', 'ECC Key 2', 'ECC Key 3', 'ECC Key 4', 'ECC Key 5', 'ECC Key 6', 'ECC Key 7', 'ECC Key 8', 'ECC Key 9', 'ECC Key 10', 'ECC Key 11', 'ECC Key 12', 'ECC Key 13', 'ECC Key 14', 'ECC Key 15', 'ECC Key 16'])
            for slot_name in slots:
                print(tmp[slot_name].to_str().replace('ÿ'," "))
        elif sys.argv[1] == 'setslot':
            try:
                if sys.argv[2] == '1a':
                    slot_id = 1
                elif sys.argv[2] == '2a':
                    slot_id = 2
                elif sys.argv[2] == '3a':
                    slot_id = 3
                elif sys.argv[2] == '4a':
                    slot_id = 4
                elif sys.argv[2] == '5a':
                    slot_id = 5
                elif sys.argv[2] == '6a':
                    slot_id = 6
                elif sys.argv[2] == '1b':
                    slot_id = 7
                elif sys.argv[2] == '2b':
                    slot_id = 8
                elif sys.argv[2] == '3b':
                    slot_id = 9
                elif sys.argv[2] == '4b':
                    slot_id = 10
                elif sys.argv[2] == '5b':
                    slot_id = 11
                elif sys.argv[2] == '6b':
                    slot_id = 12
                elif sys.argv[2] == 'green1a':
                    slot_id = 1
                elif sys.argv[2] == 'green2a':
                    slot_id = 2
                elif sys.argv[2] == 'green3a':
                    slot_id = 3
                elif sys.argv[2] == 'green1b':
                    slot_id = 4
                elif sys.argv[2] == 'green2b':
                    slot_id = 5
                elif sys.argv[2] == 'green3b':
                    slot_id = 6
                elif sys.argv[2] == 'blue1a':
                    slot_id = 7
                elif sys.argv[2] == 'blue2a':
                    slot_id = 8
                elif sys.argv[2] == 'blue3a':
                    slot_id = 9
                elif sys.argv[2] == 'blue1b':
                    slot_id = 10
                elif sys.argv[2] == 'blue2b':
                    slot_id = 11
                elif sys.argv[2] == 'blue3b':
                    slot_id = 12
                elif sys.argv[2] == 'yellow1a':
                    slot_id = 13
                elif sys.argv[2] == 'yellow2a':
                    slot_id = 14
                elif sys.argv[2] == 'yellow3a':
                    slot_id = 15
                elif sys.argv[2] == 'yellow1b':
                    slot_id = 16
                elif sys.argv[2] == 'yellow2b':
                    slot_id = 17
                elif sys.argv[2] == 'yellow3b':
                    slot_id = 18
                elif sys.argv[2] == 'purple1a':
                    slot_id = 19
                elif sys.argv[2] == 'purple2a':
                    slot_id = 20
                elif sys.argv[2] == 'purple3a':
                    slot_id = 21
                elif sys.argv[2] == 'purple1b':
                    slot_id = 22
                elif sys.argv[2] == 'purple2b':
                    slot_id = 23
                elif sys.argv[2] == 'purple3b':
                    slot_id = 24
                else:
                    slot_id = int(sys.argv[2])
            except:
                print("setslot [id] [type] [value]")
                print("[id] must be a valid slot number")
                return

            if sys.argv[3] == 'label':
                only_key.setslot(slot_id, MessageField.LABEL, sys.argv[4])
            elif sys.argv[3] == 'ecckeylabel':
                only_key.setslot(slot_id+28, MessageField.LABEL, sys.argv[4])
            elif sys.argv[3] == 'rsakeylabel':
                only_key.setslot(slot_id+24, MessageField.LABEL, sys.argv[4])
            elif sys.argv[3] == 'url':
                only_key.setslot(slot_id, MessageField.URL, sys.argv[4])
            elif sys.argv[3] == 'addchar2':
                only_key.setslot(slot_id, MessageField.NEXTKEY1, sys.argv[4])
            elif sys.argv[3] == 'delay1':
                only_key.setslot(slot_id, MessageField.DELAY1, sys.argv[4])
            elif sys.argv[3] == 'username':
                only_key.setslot(slot_id, MessageField.USERNAME, sys.argv[4])
            elif sys.argv[3] == 'addchar3':
                only_key.setslot(slot_id, MessageField.NEXTKEY2, sys.argv[4])
            elif sys.argv[3] == 'delay2':
                only_key.setslot(slot_id, MessageField.DELAY2, sys.argv[4])
            elif sys.argv[3] == 'password':
                password = prompt_pass()
                only_key.setslot(slot_id, MessageField.PASSWORD, password)
            elif sys.argv[3] == 'addchar5':
                only_key.setslot(slot_id, MessageField.NEXTKEY3, sys.argv[4])
            elif sys.argv[3] == 'delay3':
                only_key.setslot(slot_id, MessageField.DELAY3, sys.argv[4])
            elif sys.argv[3] == '2fa':
                 only_key.setslot(slot_id, MessageField.TFATYPE, sys.argv[4])
            elif sys.argv[3] == 'gkey':
                totpkey = prompt_key()
                totpkey = base64.b32decode("".join(totpkey.split()).upper())
                totpkey = binascii.hexlify(totpkey)
                # pad with zeros for even digits
                totpkey = totpkey.zfill(len(totpkey) + len(totpkey) % 2)
                payload = [int(totpkey[i: i+2], 16) for i in range(0, len(totpkey), 2)]
                only_key.setslot(slot_id, MessageField.TOTPKEY, payload)
            elif sys.argv[3] == 'totpkey':
                totpkey = prompt_key()
                only_key.setslot(slot_id, MessageField.TOTPKEY, totpkey)
            elif sys.argv[3] == 'addchar1':
                only_key.setslot(slot_id, MessageField.NEXTKEY4, sys.argv[4])
            elif sys.argv[3] == 'addchar4':
                only_key.setslot(slot_id, MessageField.NEXTKEY5, sys.argv[4])
            elif sys.argv[3] == 'typespeed':
                only_key.setslot(slot_id, MessageField.KEYTYPESPEED, int(sys.argv[4]))
            else:
                print("setslot [id] [type] [value]")
                print("[type] must be ['label', 'ecckeylabel', 'rsakeylabel', 'url', 'addchar1', 'delay1', 'username', 'addchar2', 'delay2', 'password', 'addchar3', 'delay3', '2fa', 'totpkey', 'addchar4', 'addchar5', 'typespeed']")
            return
        elif sys.argv[1] == 'wipeslot':
            try:
                if sys.argv[2] == '1a':
                    slot_id = 1
                elif sys.argv[2] == '2a':
                    slot_id = 2
                elif sys.argv[2] == '3a':
                    slot_id = 3
                elif sys.argv[2] == '4a':
                    slot_id = 4
                elif sys.argv[2] == '5a':
                    slot_id = 5
                elif sys.argv[2] == '6a':
                    slot_id = 6
                elif sys.argv[2] == '1b':
                    slot_id = 7
                elif sys.argv[2] == '2b':
                    slot_id = 8
                elif sys.argv[2] == '3b':
                    slot_id = 9
                elif sys.argv[2] == '4b':
                    slot_id = 10
                elif sys.argv[2] == '5b':
                    slot_id = 11
                elif sys.argv[2] == '6b':
                    slot_id = 12
                elif sys.argv[2] == 'green1a':
                    slot_id = 1
                elif sys.argv[2] == 'green2a':
                    slot_id = 2
                elif sys.argv[2] == 'green3a':
                    slot_id = 3
                elif sys.argv[2] == 'green1b':
                    slot_id = 4
                elif sys.argv[2] == 'green2b':
                    slot_id = 5
                elif sys.argv[2] == 'green3b':
                    slot_id = 6
                elif sys.argv[2] == 'blue1a':
                    slot_id = 7
                elif sys.argv[2] == 'blue2a':
                    slot_id = 8
                elif sys.argv[2] == 'blue3a':
                    slot_id = 9
                elif sys.argv[2] == 'blue1b':
                    slot_id = 10
                elif sys.argv[2] == 'blue2b':
                    slot_id = 11
                elif sys.argv[2] == 'blue3b':
                    slot_id = 12
                elif sys.argv[2] == 'yellow1a':
                    slot_id = 13
                elif sys.argv[2] == 'yellow2a':
                    slot_id = 14
                elif sys.argv[2] == 'yellow3a':
                    slot_id = 15
                elif sys.argv[2] == 'yellow1b':
                    slot_id = 16
                elif sys.argv[2] == 'yellow2b':
                    slot_id = 17
                elif sys.argv[2] == 'yellow3b':
                    slot_id = 18
                elif sys.argv[2] == 'purple1a':
                    slot_id = 19
                elif sys.argv[2] == 'purple2a':
                    slot_id = 20
                elif sys.argv[2] == 'purple3a':
                    slot_id = 21
                elif sys.argv[2] == 'purple1b':
                    slot_id = 22
                elif sys.argv[2] == 'purple2b':
                    slot_id = 23
                elif sys.argv[2] == 'purple3b':
                    slot_id = 24
                else:
                    slot_id = int(sys.argv[2])
            except:
                print("wipeslot [id]")
                print("[id] must be a valid slot number")
                return
            only_key.wipeslot(slot_id)
        elif sys.argv[1] == 'setkey' or sys.argv[1] == 'genkey':
            try:
                slot_id = 0
                pqc_slot = False
                if sys.argv[2] == 'RSA1':
                    slot_id = 1
                elif sys.argv[2] == 'RSA2':
                    slot_id = 2
                elif sys.argv[2] == 'RSA3':
                    slot_id = 3
                elif sys.argv[2] == 'RSA4':
                    slot_id = 4
                elif sys.argv[2] == 'PQC1':
                    slot_id = 1
                    pqc_slot = True
                elif sys.argv[2] == 'PQC2':
                    slot_id = 2
                    pqc_slot = True
                elif sys.argv[2] == 'PQC3':
                    slot_id = 3
                    pqc_slot = True
                elif sys.argv[2] == 'PQC4':
                    slot_id = 4
                    pqc_slot = True
                elif sys.argv[2] == 'ECC1':
                    slot_id = 101
                elif sys.argv[2] == 'ECC2':
                    slot_id = 102
                elif sys.argv[2] == 'ECC3':
                    slot_id = 103
                elif sys.argv[2] == 'ECC4':
                    slot_id = 104
                elif sys.argv[2] == 'ECC5':
                    slot_id = 105
                elif sys.argv[2] == 'ECC6':
                    slot_id = 106
                elif sys.argv[2] == 'ECC7':
                    slot_id = 107
                elif sys.argv[2] == 'ECC8':
                    slot_id = 108
                elif sys.argv[2] == 'ECC9':
                    slot_id = 109
                elif sys.argv[2] == 'ECC10':
                    slot_id = 110
                elif sys.argv[2] == 'ECC11':
                    slot_id = 111
                elif sys.argv[2] == 'ECC12':
                    slot_id = 112
                elif sys.argv[2] == 'ECC13':
                    slot_id = 113
                elif sys.argv[2] == 'ECC14':
                    slot_id = 114
                elif sys.argv[2] == 'ECC15':
                    slot_id = 115
                elif sys.argv[2] == 'ECC16':
                    slot_id = 116
                elif sys.argv[2] == 'HMAC1':
                    slot_id = 130
                elif sys.argv[2] == 'HMAC2':
                    slot_id = 129
                # PQC1-PQC4 name the same physical slots as RSA1-RSA4; the name
                # says which kind of key is going in, and these two checks keep
                # the name and the type honest in both directions. Without them
                # the pair is decorative: `setkey PQC1 n d <rsa>` would load an
                # RSA key into a slot the user called PQC.
                if pqc_slot and sys.argv[3] != 'p':
                    print("PQC%d holds a composite PQC PGP key: setkey PQC%d p <320 hex chars>."
                          % (slot_id, slot_id))
                    print("For an RSA key in that slot, name it RSA%d." % slot_id)
                    return
                if sys.argv[3] == 'p' and not pqc_slot:
                    print("A composite PQC PGP key goes in a PQC slot: setkey PQC1-PQC4 p <320 hex chars>.")
                    return
                if (sys.argv[1]=='genkey'):
                    if (slot_id > 100 and (sys.argv[3] in ('x', 'n', 's', 'c', 'm', 'w'))):
                        only_key.setkey(slot_id, sys.argv[3], sys.argv[4], 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')
                    else:
                        # No composite entry here on purpose. genkey sends the
                        # all-FFs trigger, and okcrypto_generate_random_key()
                        # is gated on `buffer[5] > 100` - ECC slots only - so a
                        # composite key cannot be generated on the device at
                        # all. It is made off-device and loaded.
                        print('Input error. See available commands with examples here https://docs.crp.to/command-line.html')
                elif (sys.argv[3] == 'p'):
                    # setkey PQC<1-4> p <320 hex chars>
                    #
                    # Three arguments, not four: a composite key is always
                    # decrypt AND sign, so there is no feature letter to pick.
                    # client.py's setkey() rejects one rather than ignoring it.
                    only_key.setkey(slot_id, 'p', '', sys.argv[4])
                elif (sys.argv[3]=='label'):
                    if slot_id > 100:
                        slot_id = slot_id - 72
                    elif slot_id >= 1:
                        slot_id = slot_id + 24
                    only_key.setslot(slot_id, MessageField.LABEL, sys.argv[4])
                else:
                    only_key.setkey(slot_id, sys.argv[3], sys.argv[4], sys.argv[5])
            except Exception as e:
                # A refused composite load raises with the device's own words
                # ("OnlyKey refused the key load: Error not in config mode").
                # This printed only the exception CLASS and exited 0, so the
                # reason was lost and a script could not tell a refusal from a
                # load. setpqc had the same shape and was fixed; setkey p is
                # its replacement and must not regress it.
                if str(e) and not isinstance(e, (IndexError, KeyError)):
                    print(str(e))
                else:
                    print(sys.exc_info()[0])
                    print('Input error. See available commands with examples here https://docs.crp.to/command-line.html')
                sys.exit(1)
        elif sys.argv[1] == 'loadpqc':
            # Load a composite PQC PGP key (IETF OpenPGP-PQC) into an RSA slot.
            # loadpqc <keyfile.asc> [PQC1-PQC4] [passphrase]
            #
            # Parses an armored composite private key through the OpenPGP.js
            # bridge (needs Node.js) and sends the 160-byte seed blob. This is
            # the only way a composite key reaches the device: the firmware has
            # no keygen trigger in the RSA slot path, and OKSETPRIV is not
            # reachable over the browser's FIDO2 transport at all.
            try:
                from . import pqc, pgp_bridge
                keyfile = sys.argv[2]
                # Composite PQC keys occupy the 4 RSA key slots on the device,
                # but the CLI names them PQC1-PQC4 and only that. setkey is
                # strict about the pair - `setkey PQC1 n d` and `setkey RSA1 p`
                # are both refused - and loadpqc accepting RSA names anyway
                # would undo the point of the PQC names existing.
                slotmap = {'PQC1': 1, 'PQC2': 2, 'PQC3': 3, 'PQC4': 4}
                slot_id = slotmap.get(sys.argv[3]) if len(sys.argv) > 3 else 1
                if not slot_id:
                    print('loadpqc <keyfile> [PQC1-PQC4] [passphrase]')
                    sys.exit(1)
                passphrase = sys.argv[4] if len(sys.argv) > 4 else None
                blob = pgp_bridge.composite_blob(path=keyfile, passphrase=passphrase)
                # Raises if the device refused the load, so the success line
                # below is only ever printed for a load that happened. There is
                # no readback for a composite key - okcrypto_getpubkey() has no
                # KEYTYPE_PQC_PGP branch - so the device's own acknowledgement
                # is the only thing that distinguishes a stored key from an
                # empty slot.
                pqc.load_composite_key(only_key, slot_id, blob)
                print('Loaded composite PQC PGP key from %s (%d bytes) into PQC%d'
                      % (keyfile, len(blob), slot_id))
            except Exception:
                print(sys.exc_info()[1])
                print('loadpqc <keyfile> [PQC1-PQC4] [passphrase]')
                sys.exit(1)
        elif sys.argv[1] == 'signpqc':
            # Sign a digest with ONE half of a composite PQC PGP key.
            # signpqc [PQC1-PQC4] [ecc|pqc] [digest hex | file]
            #   ecc -> Ed25519,    64-byte signature
            #   pqc -> ML-DSA-65,  3309-byte signature
            #
            # This is the device PRIMITIVE, not a PGP message signer: a
            # composite OpenPGP signature is the two halves concatenated, and
            # assembling that packet is the caller's job (openpgp.js does it
            # for the web app). Exposing the primitive is what lets a shell
            # script, or an independent implementation's test harness, get a
            # real signature out of the device at all.
            try:
                from . import pqc
                # Composite PQC keys occupy the 4 RSA key slots on the device,
                # but the CLI names them PQC1-PQC4 and only that. setkey is
                # strict about the pair - `setkey PQC1 n d` and `setkey RSA1 p`
                # are both refused - and loadpqc accepting RSA names anyway
                # would undo the point of the PQC names existing.
                slotmap = {'PQC1': 1, 'PQC2': 2, 'PQC3': 3, 'PQC4': 4}
                halfmap = {'ecc': pqc.HALF_ECC, 'pqc': pqc.HALF_PQC}
                if len(sys.argv) < 5:
                    print('signpqc [PQC1-PQC4] [ecc|pqc] [digest hex | file]')
                    sys.exit(1)
                slot_id = slotmap.get(sys.argv[2])
                half = halfmap.get(sys.argv[3].lower())
                if not slot_id or half is None:
                    print('signpqc [PQC1-PQC4] [ecc|pqc] [digest hex | file]')
                    sys.exit(1)
                digest = _pqc_input_bytes(sys.argv[4])
                print('Press the three buttons shown on your OnlyKey to confirm signing...',
                      file=sys.stderr)
                sig = pqc.sign(only_key, slot_id, half, digest)
                print(binascii.hexlify(sig).decode())
            except SystemExit:
                raise
            except Exception:
                print(sys.exc_info()[1])
                print('signpqc [PQC1-PQC4] [ecc|pqc] [digest hex | file]')
                sys.exit(1)
        elif sys.argv[1] == 'decryptpqc':
            # Decapsulate with ONE half of a composite PQC PGP key.
            # decryptpqc [PQC1-PQC4] [hex | file]
            #
            # The device picks the half by INPUT SIZE - there is no selector:
            #   32 bytes   -> X25519 ephemeral point -> 32-byte shared secret
            #   1088 bytes -> ML-KEM-768 ciphertext  -> 32-byte shared secret
            #
            # Again a primitive. Recovering an OpenPGP session key from these
            # needs the SHA3-256 key combine of draft-ietf-openpgp-pqc-10
            # section 4.2.1 - over both key shares, the ECDH ciphertext and
            # public key, the algorithm ID, and "OpenPGPCompositeKDFv1" with its
            # length - and an RFC 3394 AES-256 key-unwrap on top, which the
            # caller does.
            try:
                from . import pqc
                # Composite PQC keys occupy the 4 RSA key slots on the device,
                # but the CLI names them PQC1-PQC4 and only that. setkey is
                # strict about the pair - `setkey PQC1 n d` and `setkey RSA1 p`
                # are both refused - and loadpqc accepting RSA names anyway
                # would undo the point of the PQC names existing.
                slotmap = {'PQC1': 1, 'PQC2': 2, 'PQC3': 3, 'PQC4': 4}
                if len(sys.argv) < 4:
                    print('decryptpqc [PQC1-PQC4] [32-byte X25519 point or 1088-byte ML-KEM ct: hex | file]')
                    sys.exit(1)
                slot_id = slotmap.get(sys.argv[2])
                if not slot_id:
                    print('decryptpqc [PQC1-PQC4] [hex | file]')
                    sys.exit(1)
                data = _pqc_input_bytes(sys.argv[3])
                print('Press the three buttons shown on your OnlyKey to confirm decryption...',
                      file=sys.stderr)
                shared = pqc.decrypt(only_key, slot_id, data)
                print(binascii.hexlify(shared).decode())
            except SystemExit:
                raise
            except Exception:
                print(sys.exc_info()[1])
                print('decryptpqc [PQC1-PQC4] [hex | file]')
                sys.exit(1)
        elif sys.argv[1] == 'wipekey':
            try:
                if sys.argv[2] == 'RSA1':
                    slot_id = 1
                elif sys.argv[2] == 'RSA2':
                    slot_id = 2
                elif sys.argv[2] == 'RSA3':
                    slot_id = 3
                elif sys.argv[2] == 'RSA4':
                    slot_id = 4
                elif sys.argv[2] == 'PQC1':
                    slot_id = 1
                elif sys.argv[2] == 'PQC2':
                    slot_id = 2
                elif sys.argv[2] == 'PQC3':
                    slot_id = 3
                elif sys.argv[2] == 'PQC4':
                    slot_id = 4
                elif sys.argv[2] == 'ECC1':
                    slot_id = 101
                elif sys.argv[2] == 'ECC2':
                    slot_id = 102
                elif sys.argv[2] == 'ECC3':
                    slot_id = 103
                elif sys.argv[2] == 'ECC4':
                    slot_id = 104
                elif sys.argv[2] == 'ECC5':
                    slot_id = 105
                elif sys.argv[2] == 'ECC6':
                    slot_id = 106
                elif sys.argv[2] == 'ECC7':
                    slot_id = 107
                elif sys.argv[2] == 'ECC8':
                    slot_id = 108
                elif sys.argv[2] == 'ECC9':
                    slot_id = 109
                elif sys.argv[2] == 'ECC10':
                    slot_id = 110
                elif sys.argv[2] == 'ECC11':
                    slot_id = 111
                elif sys.argv[2] == 'ECC12':
                    slot_id = 112
                elif sys.argv[2] == 'ECC13':
                    slot_id = 113
                elif sys.argv[2] == 'ECC14':
                    slot_id = 114
                elif sys.argv[2] == 'ECC15':
                    slot_id = 115
                elif sys.argv[2] == 'ECC16':
                    slot_id = 116
                elif sys.argv[2] == 'HMAC1':
                    slot_id = 130
                elif sys.argv[2] == 'HMAC2':
                    slot_id = 129
            except:
                print("wipekey [key id] [type]")
                print("[key id] must be a supported key number")
                return
            only_key.wipekey(slot_id)
        elif sys.argv[1] == 'idletimeout':
             only_key.setslot(1, MessageField.IDLETIMEOUT, int(sys.argv[2]))
        elif sys.argv[1] == 'wipemode':
             only_key.setslot(1, MessageField.WIPEMODE, int(sys.argv[2]))
        elif sys.argv[1] == 'keytypespeed':
             only_key.setslot(99, MessageField.KEYTYPESPEED, int(sys.argv[2]))
        elif sys.argv[1] == 'ledbrightness':
             only_key.setslot(1, MessageField.LEDBRIGHTNESS, int(sys.argv[2]))
        elif sys.argv[1] == 'touchsense':
            only_key.setslot(1, MessageField.TOUCHSENSE, int(sys.argv[2]))
        elif sys.argv[1] in ('storedkeymode', 'derivedkeymode',
                             'webagentderivemode', 'webderivemode'):
            # User input mode, one enum for all three surfaces: 0 = challenge
            # code, 1 = button press, 2 = no press. Default is 1. For
            # stored/derived keys, 2 is only honoured by firmware built with
            # OK_ALLOW_NO_PRESS (the device answers "Error unsupported user
            # input mode" otherwise); for web/agent derived keys it is always
            # allowed. The KEY never depends on this - it is authorisation only.
            #
            # webagentderivemode is the current name for field 30 because it
            # governs slot 128 on BOTH transports, the web app and a local
            # agent over HID alike; webderivemode stays as an alias.
            field = {'storedkeymode': MessageField.PGPCHALENGEMODE,
                     'derivedkeymode': MessageField.SSHCHALENGEMODE,
                     'webagentderivemode': MessageField.WEBDERIVEMODE,
                     'webderivemode': MessageField.WEBDERIVEMODE}[sys.argv[1]]
            if len(sys.argv) < 3 or sys.argv[2] not in ('0', '1', '2'):
                print('%s [0 = challenge code | 1 = button press | 2 = no press]' % sys.argv[1])
                sys.exit(1)
            only_key.setslot(1, field, int(sys.argv[2]))
        elif sys.argv[1] == 'webcryptpolicy':
            # Field 31 bitfield: 0 = derived keys only (stored-key PGP off,
            # extension on), 1 = also allow stored-key PGP over FIDO2,
            # 2 = disable the FIDO2 extension entirely, 3 = both bits.
            # Never written (new or upgraded key) behaves as 1, like v3.0.4.
            # The firmware refuses undefined bits rather than masking them,
            # so the host validates the same range instead of guessing.
            if len(sys.argv) < 3 or sys.argv[2] not in ('0', '1', '2', '3'):
                print('webcryptpolicy [0 | 1 = allow stored-key PGP over FIDO2 |'
                      ' 2 = disable FIDO2 extension | 3 = both]')
                sys.exit(1)
            only_key.setslot(1, WEBCRYPTPOLICY_FIELD, int(sys.argv[2]))
        elif sys.argv[1] == 'backupkeymode':
             only_key.setslot(1, MessageField.BACKUPMODE, int(sys.argv[2]))
        elif sys.argv[1] == 'keylayout':
             only_key.setslot(1, MessageField.KEYLAYOUT, int(sys.argv[2]))
        elif sys.argv[1] == 'sysadminmode':
             only_key.setslot(1, MessageField.SYSADMINMODE, int(sys.argv[2]))
        elif sys.argv[1] == 'lockbutton':
             only_key.setslot(1, MessageField.LOCKBUTTON, int(sys.argv[2]))
        elif sys.argv[1] == 'hmackeymode':
             only_key.setslot(1, MessageField.HMACMODE, int(sys.argv[2]))
        elif sys.argv[1] == 'loadkey':
            try:
                # loadkey <keyfile> [slot] [features]
                # slot: RSA1-RSA4, ECC1-ECC16, or 'auto' (default)
                # features: d (decryption), s (signing), b (backup)
                keyfile = sys.argv[2]
                slot = 99  # auto by default
                features = ''
                if len(sys.argv) > 3:
                    slot_arg = sys.argv[3]
                    if slot_arg == 'auto':
                        slot = 99
                    elif slot_arg.startswith('RSA'):
                        slot = int(slot_arg[3:])
                    elif slot_arg.startswith('ECC'):
                        slot = 100 + int(slot_arg[3:])
                    else:
                        slot = int(slot_arg)
                if len(sys.argv) > 4:
                    features = sys.argv[4]
                with open(keyfile, 'r') as f:
                    key_data = f.read()
                passphrase = prompt('Passphrase: ',
                                   is_password=Condition(lambda: hidden[0]),
                                   key_bindings=key_bindings)
                only_key.loadkey(key_data, passphrase, slot=slot, key_features=features)
            except Exception as e:
                print('Error loading key: {}'.format(str(e)))
                print('Usage: onlykey-cli loadkey <keyfile> [slot] [features]')
                print('  slot: RSA1-RSA4, ECC1-ECC16, or auto (default)')
                print('  features: d (decryption), s (signing), b (backup)')
                return
        elif sys.argv[1] == 'restore':
            try:
                backupfile = sys.argv[2]
                with open(backupfile, 'r') as f:
                    backup_data = f.read()
                only_key.restore_from_backup(backup_data)
            except IndexError:
                print('Usage: onlykey-cli restore <backupfile>')
                return
            except Exception as e:
                print('Error restoring backup: {}'.format(str(e)))
                return
        elif sys.argv[1] == 'backuppassphrase':
            try:
                print('Type Control-T to toggle passphrase visible.')
                passphrase1 = prompt('Backup Passphrase: ',
                                    is_password=Condition(lambda: hidden[0]),
                                    key_bindings=key_bindings)
                passphrase2 = prompt('Confirm Passphrase: ',
                                    is_password=Condition(lambda: hidden[0]),
                                    key_bindings=key_bindings)
                if passphrase1 != passphrase2:
                    print('Error: Passphrases do not match')
                    return
                only_key.set_backup_passphrase(passphrase1)
            except Exception as e:
                print('Error setting backup passphrase: {}'.format(str(e)))
                return
        elif sys.argv[1] == 'loadfirmware':
            try:
                fwfile = sys.argv[2]
                with open(fwfile, 'r') as f:
                    fw_data = f.read()
                print('WARNING: Loading firmware will update your OnlyKey device.')
                print('Do NOT disconnect the device during the update!')
                confirm = input('Type YES to continue: ')
                if confirm.strip() != 'YES':
                    print('Firmware update cancelled.')
                    return
                only_key.load_firmware(fw_data)
            except IndexError:
                print('Usage: onlykey-cli loadfirmware <firmware_file>')
                return
            except Exception as e:
                print('Error loading firmware: {}'.format(str(e)))
                return
        elif sys.argv[1] == 'version':
            print('OnlyKey CLI v' + _cli_version())
        elif sys.argv[1] == 'capabilities':
            only_key.displaycapabilities()
        elif sys.argv[1] == 'fwversion':
            only_key.set_time(time.time())
            okversion = only_key.read_string()
            print(okversion[8:])
        elif sys.argv[1] == 'change-pin':
            if len(sys.argv) > 2:
                print('Extra option not available. See available command options here https://docs.crp.to/command-line.html')
                return
            solo.cli.key()
        elif sys.argv[1] == 'credential':
            if len(sys.argv) > 4 or len(sys.argv) < 3:
                print('Option not found. See available command options here https://docs.crp.to/command-line.html')
                return
            if sys.argv[2] == 'info' or sys.argv[2] == 'ls' or sys.argv[2] == 'rm':
                if len(sys.argv) == 4 and sys.argv[2] != 'rm':
                    print('Option not found. See available command options here https://docs.crp.to/command-line.html')
                    return
                if len(sys.argv) == 4 and sys.argv[3] == '--help':
                    print('Option not found. See available command options here https://docs.crp.to/command-line.html')
                    return
                solo.cli.key()
            else:
                print('Option not found. See available command options here https://docs.crp.to/command-line.html')
        elif sys.argv[1] == 'ping':
            if len(sys.argv) > 2:
                print('Extra option not available. See available command options here https://docs.crp.to/command-line.html')
                return
            solo.cli.key()
        elif sys.argv[1] == 'reset':
            if len(sys.argv) > 2:
                print('Extra option not available. See available command options here https://docs.crp.to/command-line.html')
                return
            solo.cli.key()
        elif sys.argv[1] == 'rng':
            if len(sys.argv) > 5 or len(sys.argv) < 3 or len(sys.argv) == 4:
                print('Option not found. See available command options here https://docs.crp.to/command-line.html')
                return
            if len(sys.argv) > 2:
                if sys.argv[2] != 'hexbytes' and sys.argv[2] != 'feedkernel':
                    print('Option not found. See available command options here https://docs.crp.to/command-line.html')
                    return
            if len(sys.argv) > 4:
                if sys.argv[3] != '--count' or len(sys.argv) != 5:
                    print('Option not found. See available command options here https://docs.crp.to/command-line.html')
                    return
                if len(sys.argv) == 5 and sys.argv[4] == '--help':
                    print('Option not found. See available command options here https://docs.crp.to/command-line.html')
                    return
            solo.cli.key()
        elif sys.argv[1] == 'set-pin':
            if len(sys.argv) > 2:
                print('Extra option not available. See available command options here https://docs.crp.to/command-line.html')
                return
            solo.cli.key()
        elif sys.argv[1] == 'wink':
            if len(sys.argv) > 2:
                print('Extra option not available. See available command options here https://docs.crp.to/command-line.html')
                return
            solo.cli.key()
        elif sys.argv[1] == '--help':
            print('See available command options here https://docs.crp.to/command-line.html')
            return
        elif sys.argv[1] == '-h':
            print('See available command options here https://docs.crp.to/command-line.html')
            return
        elif sys.argv[1] == 'help':
            print('See available command options here https://docs.crp.to/command-line.html')
            return
        elif sys.argv[1]:
            print('Command not found. See available commands here https://docs.crp.to/command-line.html')
            print()


    else:

        # Print help.
        print('OnlyKey CLI v' + _cli_version())
        print('Control-D to exit.')
        print()

        def mprompt():
            return prompt('OnlyKey> ')

        nexte = mprompt

        while 1:
            sys.argv = [sys.argv[0]]
            print()
            raw = nexte()
            print()
            data = raw.split()
            if not len(data):
                data.append('NULL')
            # nexte = prompt_pass
            if data[0] == "settime":
                only_key.set_time(time.time())
                print(only_key.read_string())
            elif data[0] == "init":
                while 1:
                    if only_key.read_string(timeout_ms=500) != 'UNINITIALIZED':
                        break
                for msg in [Message.OKSETPIN]:
                    only_key.send_message(msg=msg)
                    print(only_key.read_string())
                    print()
                    input('Press the Enter key once you are done')
                    only_key.send_message(msg=msg)
                    print(only_key.read_string())
                    only_key.send_message(msg=msg)
                    print(only_key.read_string())
                    print()
                    input('Press the Enter key once you are done')
                    only_key.send_message(msg=msg)
                    time.sleep(1.5)
                    print(only_key.read_string())
                    print()
                for msg in [Message.OKSETPDPIN]:
                    only_key.send_message(msg=msg)
                    print(only_key.read_string() + ' for second profile')
                    print()
                    input('Press the Enter key once you are done')
                    only_key.send_message(msg=msg)
                    print(only_key.read_string() + ' for second profile')
                    only_key.send_message(msg=msg)
                    print(only_key.read_string())
                    print ()
                    input('Press the Enter key once you are done')
                    only_key.send_message(msg=msg)
                    time.sleep(1.5)
                    print(only_key.read_string())
                    print()
                for msg in [Message.OKSETSDPIN]:
                    only_key.send_message(msg=msg)
                    print(only_key.read_string())
                    print()
                    input('Press the Enter key once you are done')
                    only_key.send_message(msg=msg)
                    print(only_key.read_string())
                    only_key.send_message(msg=msg)
                    print(only_key.read_string())
                    print()
                    input('Press the Enter key once you are done')
                    only_key.send_message(msg=msg)
                    time.sleep(1.5)
                    print(only_key.read_string())
                    print()
            elif data[0] == 'getlabels':
                tmp = {}      
                if not only_key.is_duo():
                    for slot in only_key.getlabels():
                        tmp[slot.name] = slot
                        slots = iter(['1a', '1b', '2a', '2b', '3a', '3b', '4a', '4b', '5a', '5b', '6a', '6b'])
                    for slot_name in slots:
                        print(tmp[slot_name].to_str().replace('ÿ'," "))
                        print(tmp[next(slots)].to_str().replace('ÿ'," "))
                        print()
                else:
                    for slot in only_key.getduolabels():
                        tmp[slot.name] = slot
                        slots = iter(['Green 1a', 'Green 2a', 'Green 3a', 'Green 1b', 'Green 2b', 'Green 3b', 'Blue 1a', 'Blue 2a', 'Blue 3a', 'Blue 1b', 'Blue 2b', 'Blue 3b', 'Yellow 1a', 'Yellow 2a', 'Yellow 3a', 'Yellow 1b', 'Yellow 2b', 'Yellow 3b', 'Purple 1a', 'Purple 2a', 'Purple 3a', 'Purple 1b', 'Purple 2b', 'Purple 3b'])
                    for slot_name in slots:
                        print(tmp[slot_name].to_str().replace('ÿ'," "))
                        print(tmp[next(slots)].to_str().replace('ÿ'," "))
                        print(tmp[next(slots)].to_str().replace('ÿ'," "))
                        print(tmp[next(slots)].to_str().replace('ÿ'," "))
                        print(tmp[next(slots)].to_str().replace('ÿ'," "))
                        print(tmp[next(slots)].to_str().replace('ÿ'," "))
                        print()
            elif data[0] == 'getkeylabels':
                tmp = {}
                for slot in only_key.getkeylabels():
                    tmp[slot.name] = slot
                slots = iter(['RSA Key 1', 'RSA Key 2', 'RSA Key 3', 'RSA Key 4', 'ECC Key 1', 'ECC Key 2', 'ECC Key 3', 'ECC Key 4', 'ECC Key 5', 'ECC Key 6', 'ECC Key 7', 'ECC Key 8', 'ECC Key 9', 'ECC Key 10', 'ECC Key 11', 'ECC Key 12', 'ECC Key 13', 'ECC Key 14', 'ECC Key 15', 'ECC Key 16'])
                for slot_name in slots:
                    print(tmp[slot_name].to_str().replace('ÿ'," "))
            elif data[0] == 'setslot':
                try:
                    if data[1] == '1a':
                        slot_id = 1
                    elif data[1] == '2a':
                        slot_id = 2
                    elif data[1] == '3a':
                        slot_id = 3
                    elif data[1] == '4a':
                        slot_id = 4
                    elif data[1] == '5a':
                        slot_id = 5
                    elif data[1] == '6a':
                        slot_id = 6
                    elif data[1] == '1b':
                        slot_id = 7
                    elif data[1] == '2b':
                        slot_id = 8
                    elif data[1] == '3b':
                        slot_id = 9
                    elif data[1] == '4b':
                        slot_id = 10
                    elif data[1] == '5b':
                        slot_id = 11
                    elif data[1] == '6b':
                        slot_id = 12
                    elif data[1] == 'green1a':
                        slot_id = 1
                    elif data[1] == 'green2a':
                        slot_id = 2
                    elif data[1] == 'green3a':
                        slot_id = 3
                    elif data[1] == 'green1b':
                        slot_id = 4
                    elif data[1] == 'green2b':
                        slot_id = 5
                    elif data[1] == 'green3b':
                        slot_id = 6
                    elif data[1] == 'blue1a':
                        slot_id = 7
                    elif data[1] == 'blue2a':
                        slot_id = 8
                    elif data[1] == 'blue3a':
                        slot_id = 9
                    elif data[1] == 'blue1b':
                        slot_id = 10
                    elif data[1] == 'blue2b':
                        slot_id = 11
                    elif data[1] == 'blue3b':
                        slot_id = 12
                    elif data[1] == 'yellow1a':
                        slot_id = 13
                    elif data[1] == 'yellow2a':
                        slot_id = 14
                    elif data[1] == 'yellow3a':
                        slot_id = 15
                    elif data[1] == 'yellow1b':
                        slot_id = 16
                    elif data[1] == 'yellow2b':
                        slot_id = 17
                    elif data[1] == 'yellow3b':
                        slot_id = 18
                    elif data[1] == 'purple1a':
                        slot_id = 19
                    elif data[1] == 'purple2a':
                        slot_id = 20
                    elif data[1] == 'purple3a':
                        slot_id = 21
                    elif data[1] == 'purple1b':
                        slot_id = 22
                    elif data[1] == 'purple2b':
                        slot_id = 23
                    elif data[1] == 'purple3b':
                        slot_id = 24
                    else:
                        slot_id = int(data[1])
                except:
                    print("setslot [id] [type] [value]")
                    print("[id] must be a valid slot number")
                    continue
                if data[2] == 'label':
                    only_key.setslot(slot_id, MessageField.LABEL, data[3])
                elif data[2] == 'ecckeylabel':
                    only_key.setslot(slot_id+28, MessageField.LABEL, data[3])
                elif data[2] == 'rsakeylabel':
                    only_key.setslot(slot_id+24, MessageField.LABEL, data[3])
                elif data[2] == 'url':
                    only_key.setslot(slot_id, MessageField.URL, data[3])
                elif data[2] == 'addchar2':
                    only_key.setslot(slot_id, MessageField.NEXTKEY1, data[3])
                elif data[2] == 'delay1':
                    only_key.setslot(slot_id, MessageField.DELAY1, data[3])
                elif data[2] == 'username':
                    only_key.setslot(slot_id, MessageField.USERNAME, data[3])
                elif data[2] == 'addchar3':
                    only_key.setslot(slot_id, MessageField.NEXTKEY2, data[3])
                elif data[2] == 'delay2':
                    only_key.setslot(slot_id, MessageField.DELAY2, data[3])
                elif data[2] == 'password':
                    password = prompt_pass()
                    only_key.setslot(slot_id, MessageField.PASSWORD, password)
                elif data[2] == 'addchar5':
                    only_key.setslot(slot_id, MessageField.NEXTKEY3, data[3])
                elif data[2] == 'delay3':
                    only_key.setslot(slot_id, MessageField.DELAY3, data[3])
                elif data[2] == '2fa':
                     only_key.setslot(slot_id, MessageField.TFATYPE, data[3])
                elif data[2] == 'gkey':
                    totpkey = prompt_key()
                    totpkey = base64.b32decode("".join(totpkey.split()).upper())
                    totpkey = binascii.hexlify(totpkey)
                    # pad with zeros for even digits
                    totpkey = totpkey.zfill(len(totpkey) + len(totpkey) % 2)
                    payload = [int(totpkey[i: i+2], 16) for i in range(0, len(totpkey), 2)]
                    only_key.setslot(slot_id, MessageField.TOTPKEY, payload)
                elif data[2] == 'totpkey':
                    totpkey = prompt_key()
                    only_key.setslot(slot_id, MessageField.TOTPKEY, totpkey)
                elif data[2] == 'addchar1':
                    only_key.setslot(slot_id, MessageField.NEXTKEY3, data[3])
                elif data[2] == 'addchar4':
                    only_key.setslot(slot_id, MessageField.NEXTKEY3, data[3])
                elif data[2] == 'typespeed':
                    only_key.setslot(slot_id, MessageField.KEYTYPESPEED, int(data[3]))
                else:
                    print("setslot [id] [type] [value]")
                    print("[type] must be ['label', 'ecckeylabel', 'rsakeylabel', 'url', 'addchar1', 'delay1', 'username', 'addchar2', 'delay2', 'password', 'addchar3', 'delay3', '2fa', 'totpkey', 'addchar4', 'addchar5', 'typespeed']")
                continue
            elif data[0] == 'wipeslot':
                try:
                    if data[1] == '1a':
                        slot_id = 1
                    elif data[1] == '2a':
                        slot_id = 2
                    elif data[1] == '3a':
                        slot_id = 3
                    elif data[1] == '4a':
                        slot_id = 4
                    elif data[1] == '5a':
                        slot_id = 5
                    elif data[1] == '6a':
                        slot_id = 6
                    elif data[1] == '1b':
                        slot_id = 7
                    elif data[1] == '2b':
                        slot_id = 8
                    elif data[1] == '3b':
                        slot_id = 9
                    elif data[1] == '4b':
                        slot_id = 10
                    elif data[1] == '5b':
                        slot_id = 11
                    elif data[1] == '6b':
                        slot_id = 12
                    elif data[1] == 'green1a':
                        slot_id = 1
                    elif data[1] == 'green2a':
                        slot_id = 2
                    elif data[1] == 'green3a':
                        slot_id = 3
                    elif data[1] == 'green1b':
                        slot_id = 4
                    elif data[1] == 'green2b':
                        slot_id = 5
                    elif data[1] == 'green3b':
                        slot_id = 6
                    elif data[1] == 'blue1a':
                        slot_id = 7
                    elif data[1] == 'blue2a':
                        slot_id = 8
                    elif data[1] == 'blue3a':
                        slot_id = 9
                    elif data[1] == 'blue1b':
                        slot_id = 10
                    elif data[1] == 'blue2b':
                        slot_id = 11
                    elif data[1] == 'blue3b':
                        slot_id = 12
                    elif data[1] == 'yellow1a':
                        slot_id = 13
                    elif data[1] == 'yellow2a':
                        slot_id = 14
                    elif data[1] == 'yellow3a':
                        slot_id = 15
                    elif data[1] == 'yellow1b':
                        slot_id = 16
                    elif data[1] == 'yellow2b':
                        slot_id = 17
                    elif data[1] == 'yellow3b':
                        slot_id = 18
                    elif data[1] == 'purple1a':
                        slot_id = 19
                    elif data[1] == 'purple2a':
                        slot_id = 20
                    elif data[1] == 'purple3a':
                        slot_id = 21
                    elif data[1] == 'purple1b':
                        slot_id = 22
                    elif data[1] == 'purple2b':
                        slot_id = 23
                    elif data[1] == 'purple3b':
                        slot_id = 24
                    else:
                        slot_id = int(data[1])
                except:
                    print("wipeslot [id]")
                    print("[id] must be a valid slot number")
                    continue
                only_key.wipeslot(slot_id)
            elif data[0] == 'setkey' or data[0] == 'genkey':
                try:
                    if data[1] == 'RSA1':
                        slot_id = 1
                    elif data[1] == 'RSA2':
                        slot_id = 2
                    elif data[1] == 'RSA3':
                        slot_id = 3
                    elif data[1] == 'RSA4':
                        slot_id = 4
                    elif data[1] == 'PQC1':
                        slot_id = 1
                    elif data[1] == 'PQC2':
                        slot_id = 2
                    elif data[1] == 'PQC3':
                        slot_id = 3
                    elif data[1] == 'PQC4':
                        slot_id = 4
                    elif data[1] == 'ECC1':
                        slot_id = 101
                    elif data[1] == 'ECC2':
                        slot_id = 102
                    elif data[1] == 'ECC3':
                        slot_id = 103
                    elif data[1] == 'ECC4':
                        slot_id = 104
                    elif data[1] == 'ECC5':
                        slot_id = 105
                    elif data[1] == 'ECC6':
                        slot_id = 106
                    elif data[1] == 'ECC7':
                        slot_id = 107
                    elif data[1] == 'ECC8':
                        slot_id = 108
                    elif data[1] == 'ECC9':
                        slot_id = 109
                    elif data[1] == 'ECC10':
                        slot_id = 110
                    elif data[1] == 'ECC11':
                        slot_id = 111
                    elif data[1] == 'ECC12':
                        slot_id = 112
                    elif data[1] == 'ECC13':
                        slot_id = 113
                    elif data[1] == 'ECC14':
                        slot_id = 114
                    elif data[1] == 'ECC15':
                        slot_id = 115
                    elif data[1] == 'ECC16':
                        slot_id = 116
                    elif data[1] == 'HMAC1':
                        slot_id = 130
                    elif data[1] == 'HMAC2':
                        slot_id = 129
                except:
                    print("setkey [key id] [type] [features]")
                    print("[key id] must be a supported key number")
                    continue
                try:
                    if (data[0]=='genkey'):
                        if (slot_id > 100 and (data[2] in ('x', 'n', 's', 'c', 'm', 'w'))):
                            only_key.setkey(slot_id, data[2], data[3], 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')
                        else:
                            print('Input error. See available commands with examples here https://docs.crp.to/command-line.html')
                    elif (data[2] == 'p'):
                        # setkey PQC<1-4> p   - the blob is prompted for, the
                        # same way RSA and ECC key material is here, so 320 hex
                        # characters of private key never land in shell history.
                        if not 1 <= slot_id <= 4:
                            print('A composite PQC PGP key goes in PQC1-PQC4.')
                            continue
                        only_key.setkey(slot_id, 'p', '', prompt_pass())
                    elif (data[2]=='label'):
                        if slot_id > 100:
                            slot_id = slot_id - 72
                        elif slot_id >= 1:
                            slot_id = slot_id + 24
                        only_key.setslot(slot_id, MessageField.LABEL, data[3])
                    else:
                        key = prompt_pass()
                        only_key.setkey(slot_id, data[2], data[3], key)
                except:
                    print(sys.exc_info()[0])
                    print('Input error. See available commands with examples here https://docs.crp.to/command-line.html')
                    continue
            elif data[0] == 'wipekey':
                try:
                    if data[1] == 'RSA1':
                        slot_id = 1
                    elif data[1] == 'RSA2':
                        slot_id = 2
                    elif data[1] == 'RSA3':
                        slot_id = 3
                    elif data[1] == 'RSA4':
                        slot_id = 4
                    elif data[1] == 'PQC1':
                        slot_id = 1
                    elif data[1] == 'PQC2':
                        slot_id = 2
                    elif data[1] == 'PQC3':
                        slot_id = 3
                    elif data[1] == 'PQC4':
                        slot_id = 4
                    elif data[1] == 'ECC1':
                        slot_id = 101
                    elif data[1] == 'ECC2':
                        slot_id = 102
                    elif data[1] == 'ECC3':
                        slot_id = 103
                    elif data[1] == 'ECC4':
                        slot_id = 104
                    elif data[1] == 'ECC5':
                        slot_id = 105
                    elif data[1] == 'ECC6':
                        slot_id = 106
                    elif data[1] == 'ECC7':
                        slot_id = 107
                    elif data[1] == 'ECC8':
                        slot_id = 108
                    elif data[1] == 'ECC9':
                        slot_id = 109
                    elif data[1] == 'ECC10':
                        slot_id = 110
                    elif data[1] == 'ECC11':
                        slot_id = 111
                    elif data[1] == 'ECC12':
                        slot_id = 112
                    elif data[1] == 'ECC13':
                        slot_id = 113
                    elif data[1] == 'ECC14':
                        slot_id = 114
                    elif data[1] == 'ECC15':
                        slot_id = 115
                    elif data[1] == 'ECC16':
                        slot_id = 116
                    elif data[1] == 'HMAC1':
                        slot_id = 130
                    elif data[1] == 'HMAC2':
                        slot_id = 129
                except:
                    print("wipekey [key id] [type]")
                    print("[key id] must be a supported key number")
                    continue
                try:
                    only_key.wipekey(slot_id)
                except:
                    continue
            elif data[0] == 'idletimeout':
                try:
                    only_key.setslot(1, MessageField.IDLETIMEOUT, int(data[1]))
                except:
                    continue
            elif data[0] == 'wipemode':
                try:
                    only_key.setslot(1, MessageField.WIPEMODE, int(data[1]))
                except:
                    continue
            elif data[0] == 'keytypespeed':
                try:
                    only_key.setslot(99, MessageField.KEYTYPESPEED, int(data[1]))
                except:
                    continue
            elif data[0] == 'ledbrightness':
                try:
                    only_key.setslot(1, MessageField.LEDBRIGHTNESS, int(data[1]))
                except:
                    continue
            elif data[0] == 'touchsense':
                try:
                    only_key.setslot(1, MessageField.TOUCHSENSE, int(data[1]))
                except:
                    continue
            elif data[0] in ('webagentderivemode', 'webderivemode'):
                try:
                    only_key.setslot(1, MessageField.WEBDERIVEMODE, int(data[1]))
                except:
                    continue
            elif data[0] == 'webcryptpolicy':
                try:
                    only_key.setslot(1, WEBCRYPTPOLICY_FIELD, int(data[1]))
                except:
                    continue
            elif data[0] == 'storedkeymode':
                try:
                    only_key.setslot(1, MessageField.PGPCHALENGEMODE, int(data[1]))
                except:
                    continue
            elif data[0] == 'derivedkeymode':
                try:
                    only_key.setslot(1, MessageField.SSHCHALENGEMODE, int(data[1]))
                except:
                    continue
            elif data[0] == 'webderivemode':
                try:
                    only_key.setslot(1, MessageField.WEBDERIVEMODE, int(data[1]))
                except:
                    continue
            elif data[0] == 'backupkeymode':
                try:
                    only_key.setslot(1, MessageField.BACKUPMODE, int(data[1]))
                except:
                    continue
            elif data[0] == 'keylayout':
                try:
                    only_key.setslot(1, MessageField.KEYLAYOUT, int(data[1]))
                except:
                    continue
            elif data[0] == 'sysadminmode':
                try:
                    only_key.setslot(1, MessageField.SYSADMINMODE, int(data[1]))
                except:
                    continue
            elif data[0] == 'lockbutton':
                try:
                    only_key.setslot(1, MessageField.LOCKBUTTON, int(data[1]))
                except:
                    continue
            elif data[0] == 'hmackeymode':
                try:
                    only_key.setslot(1, MessageField.HMACMODE, int(data[1]))
                except:
                    continue
            elif data[0] == 'loadkey':
                try:
                    keyfile = data[1]
                    slot = 99
                    features = ''
                    if len(data) > 2:
                        slot_arg = data[2]
                        if slot_arg == 'auto':
                            slot = 99
                        elif slot_arg.startswith('RSA'):
                            slot = int(slot_arg[3:])
                        elif slot_arg.startswith('ECC'):
                            slot = 100 + int(slot_arg[3:])
                        else:
                            slot = int(slot_arg)
                    if len(data) > 3:
                        features = data[3]
                    with open(keyfile, 'r') as f:
                        key_data = f.read()
                    passphrase = prompt('Passphrase: ',
                                       is_password=Condition(lambda: hidden[0]),
                                       key_bindings=key_bindings)
                    only_key.loadkey(key_data, passphrase, slot=slot, key_features=features)
                except Exception as e:
                    print('Error loading key: {}'.format(str(e)))
                    print('Usage: loadkey <keyfile> [slot] [features]')
                    print('  slot: RSA1-RSA4, ECC1-ECC16, or auto (default)')
                    print('  features: d (decryption), s (signing), b (backup)')
                    continue
            elif data[0] == 'restore':
                try:
                    backupfile = data[1]
                    with open(backupfile, 'r') as f:
                        backup_data = f.read()
                    only_key.restore_from_backup(backup_data)
                except IndexError:
                    print('Usage: restore <backupfile>')
                    continue
                except Exception as e:
                    print('Error restoring backup: {}'.format(str(e)))
                    continue
            elif data[0] == 'backuppassphrase':
                try:
                    print('Type Control-T to toggle passphrase visible.')
                    passphrase1 = prompt('Backup Passphrase: ',
                                        is_password=Condition(lambda: hidden[0]),
                                        key_bindings=key_bindings)
                    passphrase2 = prompt('Confirm Passphrase: ',
                                        is_password=Condition(lambda: hidden[0]),
                                        key_bindings=key_bindings)
                    if passphrase1 != passphrase2:
                        print('Error: Passphrases do not match')
                        continue
                    only_key.set_backup_passphrase(passphrase1)
                except Exception as e:
                    print('Error setting backup passphrase: {}'.format(str(e)))
                    continue
            elif data[0] == 'loadfirmware':
                try:
                    fwfile = data[1]
                    with open(fwfile, 'r') as f:
                        fw_data = f.read()
                    print('WARNING: Loading firmware will update your OnlyKey device.')
                    print('Do NOT disconnect the device during the update!')
                    confirm = input('Type YES to continue: ')
                    if confirm.strip() != 'YES':
                        print('Firmware update cancelled.')
                        continue
                    only_key.load_firmware(fw_data)
                except IndexError:
                    print('Usage: loadfirmware <firmware_file>')
                    continue
                except Exception as e:
                    print('Error loading firmware: {}'.format(str(e)))
                    continue
            elif data[0] == 'version':
                try:
                    print('OnlyKey CLI v' + _cli_version())
                except:
                    continue
            elif data[0] == 'capabilities':
                try:
                    only_key.displaycapabilities()
                except:
                    print(sys.exc_info()[0])
            elif data[0] == 'fwversion':
                try:
                    only_key.set_time(time.time())
                    okversion = only_key.read_string()
                    print(okversion[8:])
                except:
                    continue
            elif data[0] == 'change-pin':
                try:
                    sys.argv.append(data[0])
                    if len(data) > 1:
                        print('Extra option not available. See available command options here https://docs.crp.to/command-line.html')
                        continue
                    solo.cli.key()
                except:
                    continue
            elif data[0] == 'credential':
                try:
                    sys.argv.append(data[0])
                    if len(data) > 3 or len(data) < 2:
                        print('Option not found. See available command options here https://docs.crp.to/command-line.html')
                        continue
                    if data[1] == 'info' or data[1] == 'ls' or data[1] == 'rm':
                        sys.argv.append(data[1])
                        if len(data) == 3 and data[1] == 'rm' and data[2] != '--help':
                            sys.argv.append(data[2])
                        solo.cli.key()
                    else:
                        print('Option not found. See available command options here https://docs.crp.to/command-line.html')
                except:
                    continue
            elif data[0] == 'ping':
                try:
                    sys.argv.append(data[0])
                    if len(data) > 1:
                        print('Extra option not available. See available command options here https://docs.crp.to/command-line.html')
                        continue
                    solo.cli.key()
                except:
                    continue
            elif data[0] == 'reset':
                try:
                    sys.argv.append(data[0])
                    if len(data) > 1:
                        print('Extra option not available. See available command options here https://docs.crp.to/command-line.html')
                        continue
                    solo.cli.key()
                except:
                    continue
            elif data[0] == 'rng':
                try:
                    if len(data) > 4 or len(data) < 2:
                        print('Option not found. See available command options here https://docs.crp.to/command-line.html')
                        continue
                    sys.argv.append(data[0])
                    sys.argv.append(data[1])
                    if len(data) > 1:
                        if data[1] != 'hexbytes' and data[1] != 'feedkernel':
                            print('Option not found. See available command options here https://docs.crp.to/command-line.html')
                            continue
                    if len(data) > 2:
                        sys.argv.append(data[2])
                        if data[2] != '--count':
                            print('Option not found. See available command options here https://docs.crp.to/command-line.html')
                            continue
                    if len(data) > 3:
                        sys.argv.append(data[3])
                    solo.cli.key()
                except:
                    continue
            elif data[0] == 'set-pin':
                try:
                    sys.argv.append(data[0])
                    if len(data) > 1:
                        print('Extra option not available. See available command options here https://docs.crp.to/command-line.html')
                        continue
                    solo.cli.key()
                except:
                    continue
            elif data[0] == 'wink':
                try:
                    sys.argv.append(data[0])
                    if len(data) > 1:
                        print('Extra option not available. See available command options here https://docs.crp.to/command-line.html')
                        continue
                    solo.cli.key()
                except:
                    continue
            elif data[0] == '--help':
                try:
                    print('See available command options here https://docs.crp.to/command-line.html')
                except:
                    continue
            elif data[0] == '-h':
                try:
                    print('See available command options here https://docs.crp.to/command-line.html')
                except:
                    continue
            elif data[0] == 'help':
                try:
                    print('See available command options here https://docs.crp.to/command-line.html')
                except:
                    continue
            elif data[0] == 'exit':
                return
            elif data[0] == 'quit':
                return
            elif data[0]:
                try:
                    print('Option not found. See available command options here https://docs.crp.to/command-line.html')
                    continue
                except:
                    continue

def main():
    try:
        atexit.register(exit_handler)
        cli()
    except EOFError:
        only_key.close_if_open()
        print()
        print('Bye!')
        pass

def exit_handler():
    only_key.close_if_open()
