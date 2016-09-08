# coding: utf-8
from __future__ import unicode_literals, print_function
from prompt_toolkit import prompt
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.interface import AbortAction
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.key_binding.manager import KeyBindingManager
from prompt_toolkit.keys import Keys
from prompt_toolkit.filters import Condition


def cli():
    # Create some history first. (Easy for testing.)
    history = InMemoryHistory()
    history.append('import os')
    history.append('print("hello")')
    history.append('print("world")')
    history.append('import path')

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
        prompt('OnlyKey> ', history=history,
               auto_suggest=AutoSuggestFromHistory(),
               enable_history_search=True,
               on_abort=AbortAction.RETRY)

    nexte = mprompt

    while 1:
        text = nexte()
        print('You said: %s' % text)
        # nexte = prompt_pass

def main():
    try:
        cli()
    except EOFError:
        print()
        print('Bye!')
        pass
