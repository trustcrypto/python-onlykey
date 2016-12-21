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
    if sys.argv[1] == 'ssh':
        # SSH subcommands

        # Create a new private key
        if sys.argv[2] == 'new':
            signing_key, _ = ed25519.create_keypair()

            with open('ssh_private.key', 'wb+') as f:
                f.write(signing_key.to_seed())

            print('SSH private key written to ssh_private.key')

        # Load a private key to the OnlyKey
        elif sys.argv[2] == 'load':

            privkey = 'ssh_private.key'
            if len(privkey) == 4:
                privkey = sys.argv[3]

            if not os.path.exists(privkey):
                print('{} does not exists'.format(privkey))

            with open(privkey, 'rb') as f:
                raw_privkey = f.read()

            only_key.send_message(msg=Message.OKSETSSHPRIV, payload=raw_privkey)

            time.sleep(1.5)
            print(only_key.read_string())

    elif sys.argv[1] == 'u2f':
        print('u2f not implemented yet')

    else:
        print('unknown command')

def cli():
    logging.basicConfig(level=logging.DEBUG)
    # Create some history first. (Easy for testing.)
    history = InMemoryHistory()
    history.append('getlabels')
    history.append('setslot')
    history.append('wipeslot')

    # ContrlT handling
    hidden = [True]  # Nonlocal
    key_bindings_manager = KeyBindingManager()

    @key_bindings_manager.registry.add_binding(Keys.ControlT)
    def _(event):
        ' When ControlT has been pressed, toggle visibility. '
        hidden[0] = not hidden[0]

    def prompt_pass():
        print('Type Control-T to toggle password visible.')
        password = prompt('Password: ',
                          is_password=Condition(lambda cli: hidden[0]),
                          key_bindings_registry=key_bindings_manager.registry)
        return password

    # Print help.
    print('OnlyKey CLI v0.1')
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
        if data[0] == 'getlabels':
            tmp = {}
            for slot in only_key.getlabels():
                tmp[slot.name] = slot
            slots = iter(['1a', '1b', '2a', '2b', '3a', '3b', '4a', '4b', '5a', '5b', '6a', '6b'])
            for slot_name in slots:
                print(tmp[slot_name].to_str())
                print(tmp[next(slots)].to_str())
                print()


        elif data[0] == 'setslot':
            try:
                slot_id = int(data[1])
            except:
                print("setslot <id> <type> [value]")
                print("<id> must be an int")
                continue

            if data[2] == 'label':
                only_key.setslot(slot_id, MessageField.LABEL, data[3])
            elif data[2] == 'password':
                password = prompt_pass()
                only_key.setslot(slot_id, MessageField.PASSWORD, password)
            elif data[2] == 'type':
                only_key.setslot(slot_id, MessageField.TFATYPE, data[3])
            else:
                print("setslot <id> <type> [value]")
                print("<type> must be ['label', 'password', 'type']")
            continue
        elif data[0] == 'wipeslot':
            try:
                slot_id = int(data[1])
            except:
                print("wipeslot <id>")
                print("<id> must be an int")
                continue

            only_key.wipeslot(slot_id)
            continue


def main():
    try:
        cli()
    except EOFError:
        only_key._hid.close()
        print()
        print('Bye!')
        pass
