# coding: utf-8
from __future__ import unicode_literals, print_function

import time
import logging
import os
import sys

from prompt_toolkit import prompt
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.interface import AbortAction
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.key_binding.manager import KeyBindingManager
from prompt_toolkit.keys import Keys
from prompt_toolkit.filters import Condition
import ed25519

from client import OnlyKey, Message, MessageField

only_key = OnlyKey()


def utils():
    if sys.argv[1] == 'ecc':
        # ECC subcommands

        # Create a new private key
        if sys.argv[2] == 'new':
            signing_key, _ = ed25519.create_keypair()

            with open('ecc_private.key', 'wb+') as f:
                f.write(signing_key.to_seed())

            print('ECC private key written to ecc_private.key')

        # Load a private key to the OnlyKey
        elif sys.argv[2] == 'load':

            privkey = 'ecc_private.key'
            if len(privkey) == 4:
                privkey = sys.argv[3]

            if not os.path.exists(privkey):
                print('{} does not exists'.format(privkey))

            with open(privkey, 'rb') as f:
                raw_privkey = f.read()
                print
                print ('Enter ECC key slot number to use (1 - 32) or enter 0 to list key labels')
                print
                slot = int(raw_input())

            while slot == 0:
                ok.displaykeylabels()
                print
                print ('Enter ECC key slot number to use (1 - 32) or enter 0 to list key labels')
                print
                slot = int(raw_input())

            slot = slot + 100 # ECC keys in slot 101 - 132
            only_key.set_ecc_key(slot, (1+16+32+64+128), raw_privkey) #set ECC key with all features
            time.sleep(1.5)
            print(only_key.read_string())

    elif sys.argv[1] == 'u2f':
        print('u2f not implemented yet')

    else:
        print('unknown command')

def init():
    while 1:
        if only_key.read_string(timeout_ms=500) != 'UNINITIALIZED':
            break

    for msg in [Message.OKSETPIN, Message.OKSETPDPIN, Message.OKSETSDPIN]:
        only_key.send_message(msg=msg)
        print(only_key.read_string())
        print
        raw_input('Press the Enter key once you are done')
        only_key.send_message(msg=msg)
        print(only_key.read_string())
        only_key.send_message(msg=msg)
        print(only_key.read_string())
        print
        raw_input('Press the Enter key once you are done')
        only_key.send_message(msg=msg)
        print(only_key.read_string())
        print

def cli():
    logging.basicConfig(level=logging.DEBUG)
    # Create some history first. (Easy for testing.)
    history = InMemoryHistory()
    history.append('getlabels')
    history.append('getkeylabels')
    history.append('setslot')
    history.append('wipeslot')
    history.append('setpin')
    history.append('setsdpin')
    history.append('setpdpin')

    # ContrlT handling
    hidden = [True]  # Nonlocal
    key_bindings_manager = KeyBindingManager()

    @key_bindings_manager.registry.add_binding(Keys.ControlT)
    def _(event):
        ' When ControlT has been pressed, toggle visibility. '
        hidden[0] = not hidden[0]

    def prompt_pass():
        print('Type Control-T to toggle password visible.')
        password = prompt('Password/Key: ',
                          is_password=Condition(lambda cli: hidden[0]),
                          key_bindings_registry=key_bindings_manager.registry)
        return password

    def prompt_key():
        print('Type Control-T to toggle key visible.')
        key = prompt('Key: ',
                          is_password=Condition(lambda cli: hidden[0]),
                          key_bindings_registry=key_bindings_manager.registry)
        #need base32 to hex conversion
        return key

    def prompt_pin():
        print('Press any key when finished entering PIN')
        return


    # Print help.
    print('OnlyKey CLI v0.2')
    print('Press the right arrow to insert the suggestion.')
    print('Press Control-C to retry. Control-D to exit.')
    print()

    def mprompt():
        return prompt('OnlyKey> ',
               auto_suggest=AutoSuggestFromHistory(),
               enable_history_search=True,
               on_abort=AbortAction.RETRY)

    nexte = mprompt

    while 1:
        print()
        raw = nexte()
        print()
        data = raw.split()
        # nexte = prompt_pass
        if data[0] == "settime":
            only_key.set_time(time.time())
        elif data[0] == 'getlabels':
            tmp = {}
            for slot in only_key.getlabels():
                tmp[slot.name] = slot
            slots = iter(['1a', '1b', '2a', '2b', '3a', '3b', '4a', '4b', '5a', '5b', '6a', '6b'])
            for slot_name in slots:
                print(tmp[slot_name].to_str())
                print(tmp[next(slots)].to_str())
                print()

        if data[0] == 'getkeylabels':
            tmp = {}
            for slot in only_key.getkeylabels():
                tmp[slot.name] = slot
            slots = iter(['RSA Key 1', 'RSA Key 2', 'RSA Key 3', 'RSA Key 4', 'ECC Key 1', 'ECC Key 2', 'ECC Key 3', 'ECC Key 4', 'ECC Key 5', 'ECC Key 6', 'ECC Key 7', 'ECC Key 8', 'ECC Key 9', 'ECC Key 10', 'ECC Key 11', 'ECC Key 12', 'ECC Key 13', 'ECC Key 14', 'ECC Key 19', 'ECC Key 20', 'ECC Key 21', 'ECC Key 22', 'ECC Key 23', 'ECC Key 24', 'ECC Key 25', 'ECC Key 26', 'ECC Key 27', 'ECC Key 28', 'ECC Key 29', 'ECC Key 30', 'ECC Key 31', 'ECC Key 32'])
            for slot_name in slots:
                print(tmp[slot_name].to_str())
                print(tmp[next(slots)].to_str())

        elif data[0] == 'setslot':
            try:
                slot_id = int(data[1])
            except:
                print("setslot <id> <type> [value]")
                print("<id> must be an int (1-24)")
                continue

            if data[2] == 'label':
                only_key.setslot(slot_id, MessageField.LABEL, data[3])
            elif data[2] == 'url':
                only_key.setslot(slot_id, MessageField.URL, data[3])
            elif data[2] == 'add_char1':
                only_key.setslot(slot_id, MessageField.NEXTKEY1, data[3])
            elif data[2] == 'delay1':
                only_key.setslot(slot_id, MessageField.DELAY1, data[3])
            elif data[2] == 'username':
                only_key.setslot(slot_id, MessageField.USERNAME, data[3])
            elif data[2] == 'add_char2':
                only_key.setslot(slot_id, MessageField.NEXTKEY2, data[3])
            elif data[2] == 'delay2':
                only_key.setslot(slot_id, MessageField.DELAY2, data[3])
            elif data[2] == 'password':
                password = prompt_pass()
                only_key.setslot(slot_id, MessageField.PASSWORD, password)
            elif data[2] == 'add_char3':
                only_key.setslot(slot_id, MessageField.NEXTKEY3, data[3])
            elif data[2] == 'delay3':
                only_key.setslot(slot_id, MessageField.DELAY3, data[3])
            elif data[2] == 'type':
                 only_key.setslot(slot_id, MessageField.TFATYPE, data[3])
            elif data[2] == 'totpkey':
                totpkey = prompt_key()
                only_key.setslot(slot_id, MessageField.TOTPKEY, totpkey)
            elif data[2] == 'idletimeout':
                 only_key.setslot(slot_id, MessageField.IDLETIMEOUT, data[3])
            elif data[2] == 'wipemode':
                 only_key.setslot(slot_id, MessageField.WIPEMODE, data[3])
            elif data[2] == 'keytypespeed':
                 only_key.setslot(slot_id, MessageField.KEYTYPESPEED, data[3])
            elif data[2] == 'keylayout':
                 only_key.setslot(slot_id, MessageField.KEYLAYOUT, data[3])
            else:
                print("setslot <id> <type> [value]")
                print("<type> must be ['label', 'url', 'add_char1', 'delay1', 'username', 'add_char2', 'delay2', 'password', 'add_char3', 'delay3', 'type', 'totpkey', 'add_char4', 'delay4', 'idletimeout', 'wipemode', 'keytypespeed', 'keylayout']")
            continue
        elif data[0] == 'wipeslot':
            try:
                slot_id = int(data[1])
            except:
                print("wipeslot <id>")
                print("<id> must be an int (1-24)")
                continue

            only_key.wipeslot(slot_id)


def main():
    try:
        cli()
    except EOFError:
        only_key._hid.close()
        print()
        print('Bye!')
        pass
