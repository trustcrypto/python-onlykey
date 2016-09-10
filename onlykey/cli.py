# coding: utf-8
from __future__ import unicode_literals, print_function

import logging

from prompt_toolkit import prompt
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.interface import AbortAction
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.key_binding.manager import KeyBindingManager
from prompt_toolkit.keys import Keys
from prompt_toolkit.filters import Condition

from client import OnlyKey, Message, MessageField


def cli():
    logging.basicConfig(level=logging.DEBUG)
    only_key = OnlyKey()
    # Create some history first. (Easy for testing.)
    history = InMemoryHistory()
    history.append('getlabels')
    history.append('setslot')

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
    print('This CLI has fish-style auto-suggestion enable.')
    print('Type for instance "pri", then you\'ll see a suggestion.')
    print('Press the right arrow to insert the suggestion.')
    print('Press Control-C to retry. Control-D to exit.')
    print()

    def mprompt():
        return prompt('OnlyKey> ', history=history,
               auto_suggest=AutoSuggestFromHistory(),
               enable_history_search=True,
               on_abort=AbortAction.RETRY)

    nexte = mprompt

    while 1:
        raw = nexte()
        data = raw.split()
        # nexte = prompt_pass
        if data[0] == 'getlabels':
            for slot in only_key.getlabels():
                print(slot)
        elif data[0] == 'setslot':
            try:
                slot_id = int(data[1])
            except:
                print("setslot <id> <type> [value]")
                print("<id> must be an int")
                continue

            if data[2] == 'label':
                only_key.setslot(slot_id, MessageField.LABEL, data[3])
                print(only_key.read_string())
            elif data[2] == 'password':
                password = prompt_pass()
                only_key.setslot(slot_id, MessageField.PASSWORD, password)
                print(only_key.read_string())
            elif data[2] == 'type':
                only_key.setslot(slot_id, MessageField.TFATYPE, data[3])
                print(only_key.read_string())
            else:
                print("setslot <id> <type> [value]")
                print("<type> must be ['label', 'password', 'type']")
                continue


def main():
    try:
        cli()
    except EOFError:
        print()
        print('Bye!')
        pass
