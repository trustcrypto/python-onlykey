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

from .client import OnlyKey, Message, MessageField

only_key = OnlyKey()

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
            for slot in only_key.getlabels():
                tmp[slot.name] = slot
            slots = iter(['1a', '1b', '2a', '2b', '3a', '3b', '4a', '4b', '5a', '5b', '6a', '6b'])
            for slot_name in slots:
                print(tmp[slot_name].to_str().replace('ÿ'," "))
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
                elif sys.argv[2] >= int('25'):
                    slot_id = int(sys.argv[2])
            except:
                print("setslot <id> <type> [value]")
                print("<id> must be slot number 1a - 6b")
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
            else:
                print("setslot <id> <type> [value]")
                print("<type> must be ['label', 'ecckeylabel', 'rsakeylabel', 'url', 'addchar1', 'delay1', 'username', 'addchar2', 'delay2', 'password', 'addchar3', 'delay3', '2fa', 'totpkey', 'addchar4', 'addchar5']")
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
                elif sys.argv[2] >= int('25'):
                    slot_id = int(sys.argv[2])
            except:
                print("wipeslot <id>")
                print("<id> must be slot number 1a - 6b")
                return
            only_key.wipeslot(slot_id)
        elif sys.argv[1] == 'backupkey':
            only_key.generate_backup_key()
        elif sys.argv[1] == 'setkey':
            only_key.setkey(sys.argv[2], sys.argv[3], sys.argv[4])
        elif sys.argv[1] == 'wipekey':
            only_key.wipekey(sys.argv[2])
        elif sys.argv[1] == 'idletimeout':
             only_key.setslot(1, MessageField.IDLETIMEOUT, int(sys.argv[2]))
        elif sys.argv[1] == 'wipemode':
             only_key.setslot(1, MessageField.WIPEMODE, int(sys.argv[2]))
        elif sys.argv[1] == 'keytypespeed':
             only_key.setslot(1, MessageField.KEYTYPESPEED, int(sys.argv[2]))
        elif sys.argv[1] == 'ledbrightness':
             only_key.setslot(1, MessageField.LEDBRIGHTNESS, int(sys.argv[2]))
        elif sys.argv[1] == '2ndprofilemode':
             only_key.setslot(1, MessageField.SECPROFILEMODE, int(sys.argv[2]))
        elif sys.argv[1] == 'storedkeymode':
             only_key.setslot(1, MessageField.PGPCHALENGEMODE, int(sys.argv[2]))
        elif sys.argv[1] == 'derivedkeymode':
             only_key.setslot(1, MessageField.SSHCHALENGEMODE, int(sys.argv[2]))
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
        elif sys.argv[1] == 'version':
            print('OnlyKey CLI v1.2.4')
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
            if len(sys.argv) > 5 or len(sys.argv) < 3:
                print('Option not found. See available command options here https://docs.crp.to/command-line.html')
                return
            if len(sys.argv) > 2:
                if sys.argv[2] != 'hexbytes' and sys.argv[2] != 'feedkernel':
                    print('Option not found. See available command options here https://docs.crp.to/command-line.html')
                    return
            if len(sys.argv) > 3:
                if sys.argv[3] != '--count' or len(sys.argv) != 4:
                    print('Option not found. See available command options here https://docs.crp.to/command-line.html')
                    return
                if len(sys.argv) == 4 and sys.argv[4] == '--help':
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
        print('OnlyKey CLI v1.2.4')
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
                for slot in only_key.getlabels():
                    tmp[slot.name] = slot
                slots = iter(['1a', '1b', '2a', '2b', '3a', '3b', '4a', '4b', '5a', '5b', '6a', '6b'])
                for slot_name in slots:
                    print(tmp[slot_name].to_str().replace('ÿ'," "))
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
                    elif data[1] >= int('25'):
                        slot_id = int(data[1])
                except:
                    print("setslot <id> <type> [value]")
                    print("<id> must be slot number 1a - 6b")
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
                else:
                    print("setslot <id> <type> [value]")
                    print("<type> must be ['label', 'ecckeylabel', 'rsakeylabel', 'url', 'addchar1', 'delay1', 'username', 'addchar2', 'delay2', 'password', 'addchar3', 'delay3', '2fa', 'totpkey', 'addchar4', 'addchar5']")
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
                    elif data[1] >= int('25'):
                        slot_id = int(data[1])
                except:
                    print("wipeslot <id>")
                    print("<id> must be slot number 1a - 6b")
                    continue
                only_key.wipeslot(slot_id)
            elif data[0] == 'backupkey':
                try:
                    only_key.generate_backup_key()
                except:
                    continue
            elif data[0] == 'setkey':
                try:
                    key = prompt_pass()
                    only_key.setkey(data[1], data[2], key)
                except:
                    continue
            elif data[0] == 'wipekey':
                try:
                    only_key.wipekey(data[1])
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
                    only_key.setslot(1, MessageField.KEYTYPESPEED, int(data[1]))
                except:
                    continue
            elif data[0] == 'ledbrightness':
                try:
                    only_key.setslot(1, MessageField.LEDBRIGHTNESS, int(data[1]))
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
            elif data[0] == 'backupkeymode':
                try:
                    only_key.setslot(1, MessageField.BACKUPMODE, int(data[1]))
                except:
                    continue
            elif data[0] == '2ndprofilemode':
                try:
                    only_key.setslot(1, MessageField.SECPROFILEMODE, int(data[1]))
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
            elif data[0] == 'version':
                try:
                    print('OnlyKey CLI v1.2.4')
                except:
                    continue
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
        cli()
    except EOFError:
        only_key._hid.close()
        print()
        print('Bye!')
        pass
