# coding: utf-8
from __future__ import unicode_literals, print_function
from __future__ import absolute_import

from builtins import input
from builtins import next
from builtins import range
import base64
import binascii
import functools
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
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.keys import Keys
from prompt_toolkit.filters import Condition
import nacl.signing
from getpass import getpass
import click

from .client import OnlyKey, Message, MessageField

SLOTS = {
    "1a": 1,
    "2a": 2,
    "3a": 3,
    "4a": 4,
    "5a": 5,
    "6a": 6,
    "1b": 7,
    "2b": 8,
    "3b": 9,
    "4b": 10,
    "5b": 11,
    "6b": 12,
    "green1a": 1,
    "green2a": 2,
    "green3a": 3,
    "green1b": 4,
    "green2b": 5,
    "green3b": 6,
    "blue1a": 7,
    "blue2a": 8,
    "blue3a": 9,
    "blue1b": 10,
    "blue2b": 11,
    "blue3b": 12,
    "yellow1a": 13,
    "yellow2a": 14,
    "yellow3a": 15,
    "yellow1b": 16,
    "yellow2b": 17,
    "yellow3b": 18,
    "purple1a": 19,
    "purple2a": 20,
    "purple3a": 21,
    "purple1b": 22,
    "purple2b": 23,
    "purple3b": 24,
}


FIELDS = {
    "label": MessageField.LABEL,
    "ecckeylabel": MessageField.LABEL,
    "rsakeylabel": MessageField.LABEL,
    "url": MessageField.URL,
    "delay1": MessageField.DELAY1,
    "username": MessageField.USERNAME,
    "delay2": MessageField.DELAY2,
    "password": MessageField.PASSWORD,
    "delay3": MessageField.DELAY3,
    "2fa": MessageField.TFATYPE,
    "gkey": MessageField.TOTPKEY,
    "totpkey": MessageField.TOTPKEY,
    "addchar1": MessageField.NEXTKEY1,
    "addchar2": MessageField.NEXTKEY2,
    "addchar3": MessageField.NEXTKEY3,
    "addchar4": MessageField.NEXTKEY4,
    "addchar5": MessageField.NEXTKEY5,
    "typespeed": MessageField.KEYTYPESPEED,
}

KEYSLOTS = {
    "RSA1": 1,
    "RSA2": 2,
    "RSA3": 3,
    "RSA4": 4,
    "ECC1": 101,
    "ECC2": 102,
    "ECC3": 103,
    "ECC4": 104,
    "ECC5": 105,
    "ECC6": 106,
    "ECC7": 107,
    "ECC8": 108,
    "ECC9": 109,
    "ECC10": 110,
    "ECC11": 111,
    "ECC12": 112,
    "ECC13": 113,
    "ECC14": 114,
    "ECC15": 115,
    "ECC16": 116,
    "HMAC1": 130,
    "HMAC2": 129,
}

CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])

only_key = OnlyKey()


def rename_kwargs(**replacements):
    def actual_decorator(func):
        @functools.wraps(func)
        def decorated_func(*args, **kwargs):
            for internal_arg, external_arg in replacements.iteritems():
                if external_arg in kwargs:
                    kwargs[internal_arg] = kwargs.pop(external_arg)
            return func(*args, **kwargs)

        return decorated_func

    return actual_decorator


@click.group(context_settings=CONTEXT_SETTINGS, invoke_without_command=True)
@click.pass_context
def cli(ctx):

    logging.basicConfig(level=logging.DEBUG)

    # Control-T handling
    hidden = [True]  # Nonlocal
    key_bindings = KeyBindings()

    @key_bindings.add("c-t")
    def _(event):
        "When Control-T has been pressed, toggle visibility."
        hidden[0] = not hidden[0]

    def prompt_key():
        print("Type Control-T to toggle key visible.")
        key = prompt(
            "Key: ", is_password=Condition(lambda: hidden[0]), key_bindings=key_bindings
        )
        return key

    def prompt_pin():
        print("Press any key when finished entering PIN")
        return

    if ctx.invoked_subcommand is None:
        # Print help.
        print("OnlyKey CLI v1.2.10")
        print("Control-D to exit.")
        print()

        history = InMemoryHistory()

        def mprompt():
            return prompt(
                "OnlyKey> ",
                completer=WordCompleter(cli.commands.keys()),
                history=history,
                auto_suggest=AutoSuggestFromHistory(),
            )

        while 1:
            sys.argv = [sys.argv[0]]
            print()
            raw = mprompt()
            print()
            data = raw.split()
            if not len(data):
                continue
            try:
                cmd = cli.commands[data[0]]
            except KeyError:
                print("Unknown command")
                continue
            try:
                sub_ctx = cmd.make_context(data[0], data[1:])
                cmd.invoke(sub_ctx)
            except (click.exceptions.ClickException, Exception) as e:
                print(e)


@cli.command()
def settime():
    """A command for setting time on OnlyKey, time is needed for TOTP (Google Authenticator)"""
    only_key.set_time(time.time())
    print(only_key.read_string())


@cli.command()
def init():
    """A command line tool for setting PIN on OnlyKey (Initial Configuration)"""
    while 1:
        if only_key.read_string(timeout_ms=500) != "UNINITIALIZED":
            break
    for msg in [Message.OKSETPIN]:
        only_key.send_message(msg=msg)
        print(only_key.read_string())
        print()
        input("Press the Enter key once you are done")
        only_key.send_message(msg=msg)
        print(only_key.read_string())
        only_key.send_message(msg=msg)
        print(only_key.read_string())
        print()
        input("Press the Enter key once you are done")
        only_key.send_message(msg=msg)
        time.sleep(1.5)
        print(only_key.read_string())
        print()
    for msg in [Message.OKSETPDPIN]:
        only_key.send_message(msg=msg)
        print(only_key.read_string() + " for second profile")
        print()
        input("Press the Enter key once you are done")
        only_key.send_message(msg=msg)
        print(only_key.read_string() + " for second profile")
        only_key.send_message(msg=msg)
        print(only_key.read_string())
        print()
        input("Press the Enter key once you are done")
        only_key.send_message(msg=msg)
        time.sleep(1.5)
        print(only_key.read_string())
        print()
    for msg in [Message.OKSETSDPIN]:
        only_key.send_message(msg=msg)
        print(only_key.read_string())
        print()
        input("Press the Enter key once you are done")
        only_key.send_message(msg=msg)
        print(only_key.read_string())
        only_key.send_message(msg=msg)
        print(only_key.read_string())
        print()
        input("Press the Enter key once you are done")
        only_key.send_message(msg=msg)
        time.sleep(1.5)
        print(only_key.read_string())
        print()


@cli.command()
def getlabels():
    """Returns slot labels"""
    tmp = {}
    only_key.set_time(time.time())
    okversion = only_key.read_string()
    if okversion[19] == "c":
        for slot in only_key.getlabels():
            tmp[slot.name] = slot
            slots = iter(
                ["1a", "1b", "2a", "2b", "3a", "3b", "4a", "4b", "5a", "5b", "6a", "6b"]
            )
        for slot_name in slots:
            print(tmp[slot_name].to_str().replace("ÿ", " "))
            print(tmp[next(slots)].to_str().replace("ÿ", " "))
            print()
    else:
        for slot in only_key.getduolabels():
            tmp[slot.name] = slot
            slots = iter(
                [
                    "Green 1a",
                    "Green 2a",
                    "Green 3a",
                    "Green 1b",
                    "Green 2b",
                    "Green 3b",
                    "Blue 1a",
                    "Blue 2a",
                    "Blue 3a",
                    "Blue 1b",
                    "Blue 2b",
                    "Blue 3b",
                    "Yellow 1a",
                    "Yellow 2a",
                    "Yellow 3a",
                    "Yellow 1b",
                    "Yellow 2b",
                    "Yellow 3b",
                    "Purple 1a",
                    "Purple 2a",
                    "Purple 3a",
                    "Purple 1b",
                    "Purple 2b",
                    "Purple 3b",
                ]
            )
        for slot_name in slots:
            print(tmp[slot_name].to_str().replace("ÿ", " "))
            print(tmp[next(slots)].to_str().replace("ÿ", " "))
            print(tmp[next(slots)].to_str().replace("ÿ", " "))
            print(tmp[next(slots)].to_str().replace("ÿ", " "))
            print(tmp[next(slots)].to_str().replace("ÿ", " "))
            print(tmp[next(slots)].to_str().replace("ÿ", " "))
            print()


@cli.command()
def getkeylabels():
    """Returns key labels for RSA keys 1-4 and ECC keys 1-16"""
    tmp = {}
    for slot in only_key.getkeylabels():
        tmp[slot.name] = slot
    slots = iter(
        [
            "RSA Key 1",
            "RSA Key 2",
            "RSA Key 3",
            "RSA Key 4",
            "ECC Key 1",
            "ECC Key 2",
            "ECC Key 3",
            "ECC Key 4",
            "ECC Key 5",
            "ECC Key 6",
            "ECC Key 7",
            "ECC Key 8",
            "ECC Key 9",
            "ECC Key 10",
            "ECC Key 11",
            "ECC Key 12",
            "ECC Key 13",
            "ECC Key 14",
            "ECC Key 15",
            "ECC Key 16",
        ]
    )
    for slot_name in slots:
        print(tmp[slot_name].to_str().replace("ÿ", " "))


@cli.command()
@click.argument("id_", metavar="id")
@click.argument("type_", metavar="type")
@click.argument("value", required=False)
def setslot(id_, type_, value):
    """
    Set fields on a slot

    \b
    [id] must be slot number 1a - 6b for OnlyKey or 1-24 for OnlyKey DUO
    [type] must be one of the following:
        label - set slots (1a - 6b) to have a descriptive label i.e. My Google Acct
        url - URL to login page
        delay1 - set a 0 - 9 second delay
        addchar1 - Additional character before username 1 for TAB, 0 to clear
        username - Username to login
        addchar2 - Additional character after username 1 for TAB, 2 for RETURN
        delay2 - set a 0 - 9 second delay
        password - Password to login
        addchar3 - Additional character after password 1 for TAB, 2 for RETURN
        delay3 - set a 0 - 9 second delay
        addchar4 - Additional character before OTP 1 for TAB
        2fa - type of two factor authentication
            g - Google Authenticator
            y - Yubico OTP
            u - U2F
        totpkey - Google Authenticator key
        addchar5 - Additional character after OTP 2 for RETURN
    """
    try:
        slot_id = SLOTS[id_]
    except KeyError:
        print(f"Invalid slot {id_}. Must be one of {SLOTS.keys()}")
        return 1

    field_id = FIELDS.get(type_, None)
    if field_id is None:
        print(f"Invalid field {type_}. Must be one of {FIELDS.keys()}")

    if type_ == "ecckeylabel":
        slot_id += 28
    elif type_ == "rsakeylabel":
        slot_id += 24
    elif type_ == "password":
        value = getpass()
    elif type_ == "gkey":
        totpkey = prompt_key()
        totpkey = base64.b32decode("".join(totpkey.split()).upper())
        totpkey = binascii.hexlify(totpkey)
        # pad with zeros for even digits
        totpkey = totpkey.zfill(len(totpkey) + len(totpkey) % 2)
        value = [int(totpkey[i : i + 2], 16) for i in range(0, len(totpkey), 2)]
    elif type_ == "totpkey":
        value = prompt_key()
    elif type_ == "typespeed":
        value = int(value)

    only_key.setslot(slot_id, field_id, value)


@cli.command()
@click.argument("id_", metavar="id")
def wipeslot(id_):
    """
    Erases all information stored in a slot

    [id] must be slot number 1a - 6b for OnlyKey or 1-24 for OnlyKey DUO
    """
    try:
        slot_id = SLOTS[id_]
    except KeyError:
        print(f"Invalid slot {id_}. Must be one of {SLOTS.keys()}")
        return 1

    only_key.wipeslot(slot_id)


@cli.command()
@click.argument("keyslot")
@click.argument("keytype", metavar="type")
@click.argument("features")
@click.argument("value", required=False)
def setkey(keyslot, keytype, features, value):
    """
    Sets raw private keys and key labels, to set PEM format keys use the OnlyKey App

    \b
    [key slot] must be key number RSA1 - RSA4, ECC1 - ECC16, HMAC1 - HMAC2
    [type] must be one of the following:
        label - set to have a descriptive key label i.e. My GPG signing key
        x - X25519 Key Type (32 bytes)
        n - NIST256P1 Key Type (32 bytes)
        s - SECP256K1 Key Type (32 bytes)
        2 - RSA Key Type 2048bits (256 bytes)
        4 - RSA Key Type 4096bits (512 bytes)
        h - HMAC Key Type (20 bytes)
    [features] must be one of the following:
        s - Use for signing
        d - Use for decryption
        b - Use for encryption/decryption of backups
    For setting keys see examples: https://docs.crp.to/command-line.html#writing-private-keys-and-passwords
    """
    try:
        slot_id = KEYSLOTS[keyslot]
    except KeyError:
        print(f"Invalid slot {keyslot}. Must be one of {KEYSLOTS.keys()}")
        return 1

    if keytype == "label":
        if slot_id > 100:
            slot_id = slot_id - 72
        elif slot_id >= 1:
            slot_id = slot_id + 24
        only_key.setslot(slot_id, MessageField.LABEL, features)
        return

    if value is None:
        value = getpass()
    only_key.setkey(slot_id, keytype, features, value)


@cli.command()
@click.argument("keyslot")
@click.argument("keytype", metavar="type")
@click.argument("features")
def genkey(keyslot, keytype, features):
    """
    Generates random private key on device

    OnlyKey must be in config mode for this command. To enter config mode, press 6 for more than 5 seconds, then enter your PIN. The LED will be blinking red.

    [key slot] must be key number ECC1 - ECC16 (only ECC keys supported)

    \b
    [type] must be one of the following:
        x - X25519 Key Type (32 bytes)
        n - NIST256P1 Key Type (32 bytes)
        s - SECP256K1 Key Type (32 bytes)

    \b
    [features] must be one of the following:
        s - Use for signing
        d - Use for decryption
        b - Use for encryption/decryption of backups

    \b
    For generating key see example: https://docs.crp.to/command-line.html#writing-private-keys-and-passwords
    """
    try:
        slot_id = KEYSLOTS[keyslot]
    except KeyError:
        print(f"Invalid slot {keyslot}. Must be one of {KEYSLOTS.keys()}")
        return 1

    valid_types = ["x", "n", "s"]
    if keytype not in valid_types:
        print(f"Invalid key type {keytype}. Must be one of {valid_types}")
        return 1

    only_key.setkey(
        slot_id,
        keytype,
        features,
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    )


@cli.command()
@click.argument("key_id")
def wipekey(key_id):
    """
    Erases key stored at [key id]

    [key id] must be key number RSA1 - RSA4, ECC1 - ECC16, HMAC1 - HMAC2
    """
    try:
        slot_id = KEYSLOTS[key_id]
    except KeyError:
        print(f"Invalid slot {key_id}. Must be one of {KEYSLOTS.keys()}")
        return 1

    only_key.wipekey(slot_id)


@cli.command()
@click.argument("timeout", type=click.IntRange(min=0, max=255), default=30)
def idletimeout(timeout):
    """
    OnlyKey locks after ideletimeout is reached

    (1 – 255 minutes; default = 30; 0 to disable).
    """
    only_key.setslot(1, MessageField.IDLETIMEOUT, timeout)


@cli.command()
@click.argument("mode", type=click.IntRange(min=1, max=2))
def wipemode(mode):
    """
    Configure how the OnlyKey responds to a factory reset.

    WARNING - Setting to Full Wipe mode cannot be changed.

    1 = Sensitive Data Only (default)
    2 = Full Wipe (recommended for plausible deniability users) Entire device is wiped. Firmware must be reloaded.
    """
    only_key.setslot(1, MessageField.WIPEMODE, mode)


@cli.command()
@click.argument("speed", type=click.IntRange(min=1, max=10, clamp=True), default=7)
def keytypespeed(speed):
    """
    Set the typing speed

    1 = slowest; 10 = fastest [7 = default]
    """

    print(f"Setting typing speed to {speed}")
    only_key.setslot(99, MessageField.KEYTYPESPEED, speed)


@cli.command()
@click.argument("brightness", type=click.IntRange(min=1, max=10, clamp=True), default=8)
def ledbrightness(brightness):
    """
    Set the brightness of the LEDs

    1 = dimmest; 10 = brightest [8 = default]
    """
    print(f"Setting brightness to {brightness}")
    only_key.setslot(1, MessageField.LEDBRIGHTNESS, brightness)


@cli.command()
@click.argument(
    "sensitivity", type=click.IntRange(min=2, max=100, clamp=True), default=12
)
def touchsense(sensitivity):
    """
    Change the OnlyKey’s button touch sensitivity.

    WARNING: Setting button’s touch sensitivity lower than 5 is not recommended as this could result in inadvertent button press.

    2 = highest sensitivity; 100 = lowest sensitivity [12 = default]
    """
    print(f"Setting touch sensitivity to {sensitivity}")
    only_key.setslot(1, MessageField.TOUCHSENSE, sensitivity)


@cli.command()
@click.argument("mode", type=click.IntRange(min=0, max=1))
def storedkeymode(mode):
    """
    Enable or disable challenge for stored keys (SSH/PGP)

    0 = Challenge Code Required (default); 1 = Button Press Required

    More info: https://docs.crp.to/usersguide.html#stored-challenge-mode
    """
    only_key.setslot(1, MessageField.PGPCHALENGEMODE, mode)


@cli.command()
@click.argument("mode", type=click.IntRange(min=0, max=1))
def derivedkeymode(mode):
    """
    Enable or disable challenge for stored keys (SSH/PGP)

    0 = Challenge Code Required (default); 1 = Button Press Required

    More info: https://docs.crp.to/usersguide.html#derived-challenge-mode
    """
    only_key.setslot(1, MessageField.SSHCHALENGEMODE, mode)


@cli.command()
@click.argument("mode", type=click.IntRange(min=0, max=1))
def backupkeymode(mode):
    """
    Lock backup key so this may not be changed on device

    WARNING - Once set to “Locked” this cannot be changed unless a factory reset occurs.

    You can change your backup key/passphrase at any time by entering your PIN to put the device in config mode. By setting backup key mode to locked, the backup key/passphrase may not be changed. This setting provides extra security so that even if an adversary has your PIN and has physical access to your device they would not be able to backup and restore your data.
    """
    only_key.setslot(1, MessageField.BACKUPMODE, mode)


@cli.command()
@click.argument("mode", type=click.IntRange(min=1, max=2), default=1)
def secondprofilemode(mode):
    """
    Set during init (Initial Configuration) to set 2nd profile type

    1 = standard (default); 2 = plausible deniability
    """
    # TODO: find way to call this by 2ndprofilemode
    only_key.setslot(1, MessageField.SECPROFILEMODE, mode)


@cli.command()
@click.argument("layout", type=click.IntRange(min=1, max=28))
def keylayout(layout):
    """
    Set keyboard layout

    1 - USA_ENGLISH (Default)
    2 - CANADIAN_FRENCH
    3 - CANADIAN_MULTILINGUAL
    4 - DANISH
    5 - FINNISH
    6 - FRENCH
    7 - FRENCH_BELGIAN
    8 - FRENCH_SWISS
    9 - GERMAN
    10 - GERMAN_MAC
    11 - GERMAN_SWISS
    12 - ICELANDIC
    13 - IRISH
    14 - ITALIAN
    15 - NORWEGIAN
    16 - PORTUGUESE
    17 - PORTUGUESE_BRAZILIAN
    18 - SPANISH
    19 - SPANISH_LATIN_AMERICA
    20 - SWEDISH
    21 - TURKISH
    22 - UNITED_KINGDOM
    23 - US_INTERNATIONAL
    24 - CZECH
    25 - SERBIAN_LATIN_ONLY
    26 - HUNGARIAN
    27 - DANISH MAC
    28 - US_DVORAK
    """
    only_key.setslot(1, MessageField.KEYLAYOUT, layout)


@cli.command()
@click.argument("mode", type=click.IntRange(min=0, max=1), default=0)
def sysadminmode(mode):
    """
    Enable or disable challenge for stored keys (SSH/PGP)

    0 = Challenge Code Required (default); 1 = Button Press Required
    """
    only_key.setslot(1, MessageField.SYSADMINMODE, int(mode))


@cli.command()
@click.argument("mode", type=click.IntRange(min=0, max=1))
def lockbutton(mode):
    """
    Enable or disable challenge for stored keys (SSH/PGP)

    0 = Challenge Code Required (default); 1 = Button Press Required
    """
    only_key.setslot(1, MessageField.LOCKBUTTON, mode)


@cli.command()
@click.argument("mode", type=click.IntRange(min=0, max=1), default=0)
def hmackeymode(mode):
    """
    Enable or disable button press for HMAC challenge-response

    0 = Button Press Required (default); 1 = Button Press Not Required.

    OnlyKey supports HMAC challenge-response. By default, user input (button press) is required on OnlyKey to perform HMAC operation. For some use cases such as full-disk encryption no button press may be preferred. With “Button Press Not Required”, HMAC challenge-response operations may be performed without user interaction.
    """
    only_key.setslot(1, MessageField.HMACMODE, mode)


@cli.command()
def version():
    """Displays the version of the app"""
    print("OnlyKey CLI v1.3.0-dev")


@cli.command()
def fwversion():
    """Displays the version of the OnlyKey firmware"""
    only_key.set_time(time.time())
    okversion = only_key.read_string()
    print(okversion[8:])


cli.add_command(solo.cli.key.commands["change-pin"])
cli.add_command(solo.cli.key.commands["set-pin"])
cli.add_command(solo.cli.key.commands["reset"])
cli.add_command(solo.cli.key.commands["wink"])
cli.add_command(solo.cli.key.commands["ping"])
cli.add_command(solo.cli.key.commands["reset"])
cli.add_command(solo.cli.key.commands["credential"])
cli.add_command(solo.cli.key.commands["rng"])


def main():
    try:
        atexit.register(exit_handler)
        cli()
    except EOFError:
        only_key._hid.close()
        print()
        print("Bye!")
        pass


def exit_handler():
    only_key._hid.close()
