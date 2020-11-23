# coding: utf-8
from __future__ import unicode_literals, print_function
from __future__ import absolute_import

from builtins import input
from builtins import next
from builtins import range
import argparse
import base64
import binascii
import time
import logging
import os
import sys
import solo
import solo.operations
from .client import SLOTS_NAME, EDITABLE_SLOT_RANGE, KEYS_SLOT_RANGE
from solo.cli.key import reset, ping, rng, set_pin, change_pin, wink, raw as rngraw, feedkernel as rngfeedkernel, hexbytes as rnghexbytes
import solo.cli.key
from solo.cli.monitor import monitor
from solo.cli.program import program

from prompt_toolkit import prompt
from prompt_toolkit import Application
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.keys import Keys
from prompt_toolkit.filters import Condition
import nacl.signing



from .client import OnlyKey, Message, MessageField


AVAILABLE_LAYOUTS = {
    1: "USA_ENGLISH (Default)",
    2: "CANADIAN_FRENCH",
    3: "CANADIAN_MULTILINGUAL",
    4: "DANISH",
    5: "FINNISH",
    6: "FRENCH",
    7: "FRENCH_BELGIAN",
    8: "FRENCH_SWISS",
    9: "GERMAN",
    10: "GERMAN_MAC",
    11: "GERMAN_SWISS",
    12: "ICELANDIC",
    13: "IRISH",
    14: "ITALIAN",
    15: "NORWEGIAN",
    16: "PORTUGUESE",
    17: "PORTUGUESE_BRAZILIAN",
    18: "SPANISH",
    19: "SPANISH_LATIN_AMERICA",
    20: "SWEDISH",
    21: "TURKISH",
    22: "UNITED_KINGDOM",
    23: "US_INTERNATIONAL",
    24: "CZECH",
    25: "SERBIAN_LATIN_ONLY",
    26: "HUNGARIAN",
    27: "DANISH MAC",
    28: "US_DVORAK"
}

only_key = OnlyKey()

def init_onlykey():
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

def command_fwversion(parser, args):
    only_key.set_time(time.time())
    okversion = only_key.read_string()
    print(okversion[8:])

def command_help(parser, args):
    parser.print_help()

def command_getlabels(parser, args):
    tmp = {}
    for slot in only_key.getlabels():
        tmp[slot.name] = slot
    slots = iter(['1a', '1b', '2a', '2b', '3a', '3b', '4a', '4b', '5a', '5b', '6a', '6b'])
    for slot_name in slots:
        print(tmp[slot_name].to_str().replace('ÿ'," "))
        print(tmp[next(slots)].to_str().replace('ÿ'," "))
        print()

def command_getkeylabels(parser, args):
    tmp = {}
    for slot in only_key.getkeylabels():
        tmp[slot.name] = slot
    slots = iter(['RSA Key 1', 'RSA Key 2', 'RSA Key 3', 'RSA Key 4',
                  'ECC Key 1', 'ECC Key 2', 'ECC Key 3', 'ECC Key 4',
                  'ECC Key 5', 'ECC Key 6', 'ECC Key 7', 'ECC Key 8',
                  'ECC Key 9', 'ECC Key 10', 'ECC Key 11', 'ECC Key 12',
                  'ECC Key 13', 'ECC Key 14', 'ECC Key 15', 'ECC Key 16'])
    for slot_name in slots:
        print(tmp[slot_name].to_str().replace('ÿ'," "))

def slot_name_to_id(name):
    for i in SLOTS_NAME:
        if SLOTS_NAME[i] == name:
            return i

def parse_slot_id(slot_id_s):
    slot_id = slot_name_to_id(slot_id_s)
    if slot_id == None:
        slot_id = int(slot_id_s)
        if slot_id > 25:
            return slot_id
        else:
            return None
    else:
        return slot_id

def command_setslot(parser, args):
    slot_id = parse_slot_id(args.id)
    if args.type == 'label':
        only_key.setslot(slot_id, MessageField.LABEL, args.value)
    elif args.type == 'ecckeylabel':
        only_key.setslot(slot_id+28, MessageField.LABEL, args.value)
    elif args.type == 'rsakeylabel':
        only_key.setslot(slot_id+24, MessageField.LABEL, args.value)
    elif args.type == 'url':
        only_key.setslot(slot_id, MessageField.URL, args.value)
    elif args.type == 'addchar2':
        only_key.setslot(slot_id, MessageField.NEXTKEY1, args.value)
    elif args.type == 'delay1':
        only_key.setslot(slot_id, MessageField.DELAY1, args.value)
    elif args.type == 'username':
        only_key.setslot(slot_id, MessageField.USERNAME, args.value)
    elif args.type == 'addchar3':
        only_key.setslot(slot_id, MessageField.NEXTKEY2, args.value)
    elif args.type == 'delay2':
        only_key.setslot(slot_id, MessageField.DELAY2, args.value)
    elif args.type == 'password':
        password = prompt_pass()
        only_key.setslot(slot_id, MessageField.PASSWORD, password)
    elif args.type == 'addchar5':
        only_key.setslot(slot_id, MessageField.NEXTKEY3, args.value)
    elif args.type == 'delay3':
        only_key.setslot(slot_id, MessageField.DELAY3, args.value)
    elif args.type == '2fa':
         only_key.setslot(slot_id, MessageField.TFATYPE, args.value)
    elif args.type == 'gkey':
        totpkey = prompt_key()
        totpkey = base64.b32decode("".join(totpkey.split()).upper())
        totpkey = binascii.hexlify(totpkey)
        # pad with zeros for even digits
        totpkey = totpkey.zfill(len(totpkey) + len(totpkey) % 2)
        payload = [int(totpkey[i: i+2], 16) for i in range(0, len(totpkey), 2)]
        only_key.setslot(slot_id, MessageField.TOTPKEY, payload)
    elif args.type == 'totpkey':
        totpkey = prompt_key()
        only_key.setslot(slot_id, MessageField.TOTPKEY, totpkey)
    elif args.type == 'addchar1':
        only_key.setslot(slot_id, MessageField.NEXTKEY4, args.value)
    elif args.type == 'addchar4':
        only_key.setslot(slot_id, MessageField.NEXTKEY5, args.value)
    else:
        print("Invalid type")

def command_idletimeout(parser, args):
     only_key.setslot(1, MessageField.IDLETIMEOUT, args.time)

def command_keylayout(parser, args):
    if args.list_all:
        for k in AVAILABLE_LAYOUTS:
            print(f'{k} {AVAILABLE_LAYOUTS[k]}')
    elif args.layout_number == None:
        print("layout number missing, use one of")
        for k in AVAILABLE_LAYOUTS:
            print(f'{k} {AVAILABLE_LAYOUTS[k]}')
    else:
        print(f"setting keylayout {args.layout_number}: {AVAILABLE_LAYOUTS[args.layout_number]}")
        only_key.setslot(1, MessageField.KEYLAYOUT, int(args.layout_number))

def command_wipeslot(parser, args):
    slot_id = parse_slot_id(args.id)
    only_key.wipeslot(slot_id)

def make_simple_setslot(message):
    return lambda parser, args: only_key.setslot(1, message, int(args.value))

def command_change_pin(parser, args):
    change_pin.callback(args.serial)

def command_set_pin(parser, args):
    set_pin.callback(args.pin)

def command_ping(parser, args):
    ping.callback(args.serial, args.udp, args.ping_data)

def command_wink(parser, args):
    wink.callback(args.serial, args.udp)

def command_rng(parser, args):
    if getattr(args, "output-type") == "raw" and args.count != None:
        raise Exception("raw output type doesn't support count flag")

    if getattr(args, "output-type") == "hexbytes":
        rnghexbytes.callback(args.count, args.serial)
    elif getattr(args, "output-type") == "raw":
        rngraw.callback(args.serial)
    elif getattr(args, "output-type") == "feedkernel":
        rngfeedkernel.callback(args.count, args.serial)

def command_settime(parser, args):
    only_key.set_time(time.time())
    print(only_key.read_string())

def command_credential(parser, args):
    if args.cred_command == "rm" and args.credential_id == None:
        raise Exception("needed: <credential_id>")

    if args.cred_command == "info":
        cred_info.callback(args.pin, args.serial, args.udp)
    elif args.cred_command == "ls":
        cred_ls.callback(args.pin, args.serial, args.udp)
    elif args.cred_command == "rm":
        cred_rm.callback(args.pin, args.credential_id, args.serial, args.udp)


def setup_argparse(simple_commands):
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(title = "commands", dest="sub_command")
    version_parser = subparsers.add_parser("version", help="display the version of the app")
    fwvesion_parser = subparsers.add_parser("fwversion", help="display the version of the OnlyKey firmware")
    help_parser = subparsers.add_parser("help", help="this message")
    getlabels_parser = subparsers.add_parser("getlabels", help="return slot's labels")
    getkeylabels_parser = subparsers.add_parser("getkeylabels", help="show key's labels")
    setslot_parser = subparsers.add_parser("setslot", help="set slot action, label ...")
    editable_slot_names = list(SLOTS_NAME.values())[EDITABLE_SLOT_RANGE[0]:EDITABLE_SLOT_RANGE[1]]
    setslot_parser.add_argument("id")
    setslot_parser.add_argument("type", choices=[
        "label", "ecckeylabel", "rsakeylabel", "url", "addchar1", "delay1", "username",
        "addchar2", "delay2", "password", "addchar3", "delay3", "2fa", "totpkey", "addchar4", "addchar5"
    ])
    setslot_parser.add_argument("value")
    wipeslot_parser = subparsers.add_parser("wipeslot", help="wipe slot")
    wipeslot_parser.add_argument("id")
    wipekey_parser = subparsers.add_parser("wipekey", help="wipe key")
    wipekey_parser.add_argument("key")
    idletimeout_parser = subparsers.add_parser("idletimeout", help="OnlyKey locks after idletimeout is reached")
    idletimeout_parser.add_argument("time", help="1 – 255 minutes; default = 30; 0 to disable")
    keylayout_parser = subparsers.add_parser("keylayout", help="set keyboard layout")
    keylayout_parser.add_argument("layout_number", choices=AVAILABLE_LAYOUTS.keys(), nargs="?", type=int)
    keylayout_parser.add_argument("--list-all", action="store_true")

    for k in simple_commands:
        new_parser = subparsers.add_parser(k, help=f'set {k}')
        new_parser.add_argument("value")

    rng_parser = subparsers.add_parser("rng", help="generate rng content")
    rng_parser.add_argument("--count", default=8)
    rng_parser.add_argument("--serial")
    rng_parser.add_argument("output-type", choices=["raw", "hexbytes", "feedkernel"])

    ping_parser = subparsers.add_parser("ping", help="send ping")
    ping_parser.add_argument("--ping-data", default="pong")
    ping_parser.add_argument("--serial")
    ping_parser.add_argument("--udp", type=bool)

    wink_parser = subparsers.add_parser("wink", help="send wink command to key (blinks LED a few times).")
    wink_parser.add_argument("--serial")
    wink_parser.add_argument("--udp", type=bool)

    setkey_parser = subparsers.add_parser("setkey", help="set key in a slot")
    key_slot_names = list(SLOTS_NAME.values())[KEYS_SLOT_RANGE[0]:KEYS_SLOT_RANGE[1]]
    setkey_parser.add_argument("slot", choices=key_slot_names)
    setkey_parser.add_argument("keytype")

    init_parser = subparsers.add_parser("init", help="setup onlykey")

    cred_parser = subparsers.add_parser("credential", help="credential actions")
    cred_parser.add_argument("--pin")
    cred_parser.add_argument("--serial")
    cred_parser.add_argument("--udp", type=bool)
    cred_parser.add_argument("credential_id", default=argparse.SUPPRESS)
    return parser

def cli2():
    simple_commands = {
        "idletimeout": make_simple_setslot(MessageField.IDLETIMEOUT),
        "wipemode": make_simple_setslot(MessageField.WIPEMODE),
        "keytypespeed": make_simple_setslot(MessageField.KEYTYPESPEED),
        "ledbrightness": make_simple_setslot(MessageField.LEDBRIGHTNESS),
        "storedkeymode": make_simple_setslot(MessageField.PGPCHALENGEMODE),
        "derivedkeymode": make_simple_setslot(MessageField.SSHCHALENGEMODE),
        "backupkeymode": make_simple_setslot(MessageField.BACKUPMODE),
        "2ndprofilemode": make_simple_setslot(MessageField.SECPROFILEMODE),
        "sysadminmode": make_simple_setslot(MessageField.SYSADMINMODE),
        "lockbutton": make_simple_setslot(MessageField.LOCKBUTTON),
        "hmackeymode": make_simple_setslot(MessageField.HMACMODE),
    }

    available_commands = {
        "init": lambda parser, args: init_onlykey(),
        "version": lambda parser, args: print('OnlyKey CLI v1.2.3'),
        "fwversion": command_fwversion,
        "help": command_help,
        "getlabels": command_getlabels,
        "getkeylabels": command_getkeylabels,
        "setslot": command_setslot,
        "wipeslot": command_wipeslot,
        "idletimeout": command_idletimeout,
        "keylayout": command_keylayout,
        "settime": command_settime,
        "rng": command_rng,
        "set-pin": command_set_pin,
        "change-pin": command_change_pin,
        "wink": command_wink,
        "ping": command_ping,
        "credential": command_credential,
        "backupkey": lambda parser, args: only_key.generate_backup_key(),
        "wipekey": lambda parser, args: only_key.wipekey(args.key),
        "setkey": lambda parser, args: only_key.setkey(args.slot, args.keytype, prompt_pass())
        **simple_commands,
        None: command_help,
    }
    parser = setup_argparse(simple_commands)

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

    if len(sys.argv) == 1:
        print('Control-D to exit.')
        while True:
            line = prompt('OnlyKey> ')
            try: 
                args = parser.parse_args(line.split())
                available_commands[args.sub_command](parser, args)
            except:
                print("An error occurred")
    else:
        args = parser.parse_args()
        available_commands[args.sub_command](parser, args)


def main():
    try:
        cli2()
    except EOFError:
        only_key._hid.close()
        print()
        print('Bye!')
        pass
