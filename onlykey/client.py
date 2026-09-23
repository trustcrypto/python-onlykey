# coding: utf-8
from __future__ import print_function
from builtins import input
from builtins import chr
from builtins import range
from builtins import object
import logging
import time
import binascii
import hashlib
import os
import codecs
from enum import IntEnum

try:
    # Prefer the hidraw-backed module on Linux to avoid hid "open failed" races
    # when the OnlyKey HID interface was just used by another app (e.g. KeePassXC).
    import hidraw as hid
except ImportError:
    import hid
from aenum import Enum
from sys import platform

log = logging.getLogger(__name__)

DEVICE_IDS = [
    (0x16C0, 0x0486),  # OnlyKey
    (0x1d50, 0x60fc),  # OnlyKey
]

if os.name== 'nt':
	MAX_INPUT_REPORT_SIZE = 65
	MATX_OUTPUT_REPORT_SIZE = 65
	MESSAGE_HEADER = [0, 255, 255, 255, 255]
else:
	MAX_INPUT_REPORT_SIZE = 64
	MATX_OUTPUT_REPORT_SIZE = 64
	MESSAGE_HEADER = [255, 255, 255, 255]

MAX_FEATURE_REPORTS = 0
MAX_LARGE_PAYLOAD_SIZE = 58  # 64 - <4 bytes header> - <1 byte message> - <1 byte size|0xFF if max>


SLOTS_NAME= {
    0: '0',
    1: '1a',
    2: '2a',
    3: '3a',
    4: '4a',
    5: '5a',
    6: '6a',
    7: '1b',
    8: '2b',
    9: '3b',
    10: '4b',
    11: '5b',
    12: '6b',
    25: 'RSA Key 1',
    26: 'RSA Key 2',
    27: 'RSA Key 3',
    28: 'RSA Key 4',
    29: 'ECC Key 1',
    30: 'ECC Key 2',
    31: 'ECC Key 3',
    32: 'ECC Key 4',
    33: 'ECC Key 5',
    34: 'ECC Key 6',
    35: 'ECC Key 7',
    36: 'ECC Key 8',
    37: 'ECC Key 9',
    38: 'ECC Key 10',
    39: 'ECC Key 11',
    40: 'ECC Key 12',
    41: 'ECC Key 13',
    42: 'ECC Key 14',
    43: 'ECC Key 15',
    44: 'ECC Key 16',
    45: 'ECC Key 17',
    46: 'ECC Key 18',
    47: 'ECC Key 19',
    48: 'ECC Key 20',
    49: 'ECC Key 21',
    50: 'ECC Key 22',
    51: 'ECC Key 23',
    52: 'ECC Key 24',
    53: 'ECC Key 25',
    54: 'ECC Key 26',
    55: 'ECC Key 27',
    56: 'ECC Key 28',
    57: 'ECC Key 29',
    58: 'ECC Key 30',
    59: 'ECC Key 31',
    60: 'ECC Key 32',
}

SLOTS_NAME_DUO= {
    1: 'Green 1a',
    2: 'Green 2a',
    3: 'Green 3a',
    4: 'Green 1b',
    5: 'Green 2b',
    6: 'Green 3b',
    7: 'Blue 1a',
    8: 'Blue 2a',
    9: 'Blue 3a',
    10: 'Blue 1b',
    11: 'Blue 2b',
    12: 'Blue 3b',
    13: 'Yellow 1a',
    14: 'Yellow 2a',
    15: 'Yellow 3a',
    16: 'Yellow 1b',
    17: 'Yellow 2b',
    18: 'Yellow 3b',
    19: 'Purple 1a',
    20: 'Purple 2a',
    21: 'Purple 3a',
    22: 'Purple 1b',
    23: 'Purple 2b',
    24: 'Purple 3b',
    25: 'RSA Key 1',
    26: 'RSA Key 2',
    27: 'RSA Key 3',
    28: 'RSA Key 4',
    29: 'ECC Key 1',
    30: 'ECC Key 2',
    31: 'ECC Key 3',
    32: 'ECC Key 4',
    33: 'ECC Key 5',
    34: 'ECC Key 6',
    35: 'ECC Key 7',
    36: 'ECC Key 8',
    37: 'ECC Key 9',
    38: 'ECC Key 10',
    39: 'ECC Key 11',
    40: 'ECC Key 12',
    41: 'ECC Key 13',
    42: 'ECC Key 14',
    43: 'ECC Key 15',
    44: 'ECC Key 16',
    45: 'ECC Key 17',
    46: 'ECC Key 18',
    47: 'ECC Key 19',
    48: 'ECC Key 20',
    49: 'ECC Key 21',
    50: 'ECC Key 22',
    51: 'ECC Key 23',
    52: 'ECC Key 24',
    53: 'ECC Key 25',
    54: 'ECC Key 26',
    55: 'ECC Key 27',
    56: 'ECC Key 28',
    57: 'ECC Key 29',
    58: 'ECC Key 30',
    59: 'ECC Key 31',
    60: 'ECC Key 32',
}


# Message ids, setslot field ids and key types come from the generated protocol
# module (libraries/onlykey/protocol/onlykey-protocol.json -> onlykey/protocol.py).
# KeyTypeEnum is kept as a name for callers that imported it from here.
from .protocol import (Message, MessageField, KeyType, KeyType as KeyTypeEnum,
                       KeyFeature, UserInputMode, ReservedSlot, CLI_KEY_LETTERS,
                       CLI_KEY_FEATURES, key_type_byte, challenge_code,
                       challenge_code_str, classify_response, is_error,
                       parse_capabilities, CAPABILITIES_SELECTOR, CapabilityFlag,
                       KnownResponse)


# Field 31 (webcrypt policy) is NOT in the generated MessageField yet: the
# protocol JSON and its generator live on libraries:feat/user-input-modes,
# which is not the libraries branch currently checked out, so protocol.py
# stops at WEBDERIVEMODE = 30. Declared here so `onlykey-cli webcryptpolicy`
# keeps working, and marked so it is folded into the JSON and deleted from
# here the moment the protocol source and this tree are on the same branch.
#   bit 0  allow stored-key PGP over FIDO2 (OKWC_ALLOW_STORED_KEY)
#   bit 1  disable the FIDO2 extension entirely
# Undefined bits are refused by the firmware rather than masked.
class _ExtraMessageField(IntEnum):
    """Fields not in the generated MessageField yet. setslot() hands this to
    send_message(), which reads .name for the debug log and .value for the
    wire, so a bare int is NOT interchangeable with a MessageField member -
    it raises AttributeError: 'int' object has no attribute 'name'."""
    WEBCRYPTPOLICY = 31


WEBCRYPTPOLICY_FIELD = _ExtraMessageField.WEBCRYPTPOLICY
class OnlyKeyUnavailableException(Exception):
    """Exception raised when the connection to the OnlyKey failed."""
    pass


class Slot(object):
    def __init__(self, num, label=''):
        self.number = num
        self.label = label
        self.name = SLOTS_NAME[num]

    def __repr__(self):
        return '<Slot \'{}|{}\'>'.format(self.name, self.label)

    def to_str(self):
        return 'Slot {}: {}'.format(self.name, self.label or '<empty>')

class Slotduo(object):
    def __init__(self, num, label=''):
        self.number = num
        self.label = label
        self.name = SLOTS_NAME_DUO[num]

    def __repr__(self):
        return '<Slot \'{}|{}\'>'.format(self.name, self.label)

    def to_str(self):
        return 'Slot {}: {}'.format(self.name, self.label or '<empty>')

class OnlyKey(object):
    def __init__(self, connect=True):

        if connect:
            tries = 5
            while tries > 0:
                try:
                    self._connect()
                    logging.debug('connected')
                    return
                except Exception as E:
                    e = E
                    log.debug('connect failed, trying again in 1 second...')
                    time.sleep(1.5)
                    tries -= 1

            raise e

    def _connect(self):
        try:
            for d in hid.enumerate(0, 0):
                vendor_id = d['vendor_id']
                product_id = d['product_id']
                serial_number = d['serial_number']
                interface_number = d['interface_number']
                usage_page = d['usage_page']
                self.path = d['path']

                if (vendor_id, product_id) in DEVICE_IDS:
                    if serial_number == '1000000000':
                        if usage_page == 0xffab or interface_number == 2:
                            self._hid = hid.device()
                            self._hid.open_path(self.path)
                            self._hid.set_nonblocking(True)
                    else:
                        if usage_page == 0xf1d0 or interface_number == 1:
                            self._hid = hid.device()
                            self._hid.open_path(self.path)
                            self._hid.set_nonblocking(True)

        except:
            log.exception('failed to connect')
            raise OnlyKeyUnavailableException()

    def close(self):
        return self._hid.close()

    def initialized(self):
        return self.read_string() == 'INITIALIZED'

    def set_time(self, timestamp):
        # Hex format without leading 0x
        current_epoch_time = format(int(timestamp), 'x')
        # pad with zeros for even digits
        current_epoch_time = current_epoch_time.zfill(len(current_epoch_time) + len(current_epoch_time) % 2)
        payload = [int(current_epoch_time[i: i+2], 16) for i in range(0, len(current_epoch_time), 2)]
        self.send_message(msg=Message.OKSETTIME, payload=payload)

    def send_message(self, payload=None, msg=None, slot_id=None, message_field=None, from_ascii=False):
        """Send a message."""
        logging.debug('preparing payload for writing')
        # Initialize an empty message with the header
        raw_bytes = bytearray(MESSAGE_HEADER)

        # Append the message type (must be `Message` enum value)
        if msg:
            logging.debug('msg=%s', msg.name)
            raw_bytes.append(msg.value)

        # Append the slot ID if needed
        if slot_id:
            logging.debug('slot_id=%s', slot_id)
            if slot_id == 99:
                slot_id = 0
            raw_bytes.append(slot_id)

        # Append the message field (must be a `MessageField` enum value)
        if message_field:
            logging.debug('slot_field=%s', message_field.name)
            raw_bytes.append(message_field.value)

         # Append the raw payload, expect a string or a list of int
        if payload:
            if isinstance(payload, (str, str)):
                logging.debug('payload="%s"', payload)
                if from_ascii==True:
                    raw_bytes.extend(str.encode(payload))
                else:
                    raw_bytes.extend(bytearray.fromhex(payload))
            elif isinstance(payload, list) or isinstance(payload, bytearray):
                logging.debug('payload=%s', payload)
                raw_bytes.extend(payload)
            elif isinstance(payload, int):
                logging.debug('payload=%d', payload)
                raw_bytes.append(payload)
            else:
                raise Exception('`payload` must be either `str` or `list`')

        # Pad the ouput with 0s
        while len(raw_bytes) < MAX_INPUT_REPORT_SIZE:
            raw_bytes.append(0)

        # Send the message
        logging.debug('sending message ')
        self._hid.write(raw_bytes)

    def send_large_message(self, payload=None, msg=None, slot_id=chr(101)):
        """Wrapper for sending large message (larger than 58 bytes) in batch in a transparent way."""
        if not msg:
            raise Exception("Missing msg")

        # Split the payload in multiple chunks
        chunks = [payload[x:x+MAX_LARGE_PAYLOAD_SIZE] for x in range(0, len(payload), 58)]
        for chunk in chunks:
            # print chunk
            # print [ord(c) for c in chunk]
            current_payload = [255]  # 255 means that it's not the last payload
            # If it's less than the max size, set explicitely the size
            if len(chunk) < 58:
                current_payload = [len(chunk)]
            # Append the actual payload
            if isinstance(chunk, list):
                current_payload.extend(chunk)
            else:
                for c in chunk:
                    current_payload.append(ord(c))

            self.send_message(payload=current_payload, msg=msg)

        return


    def send_large_message2(self, payload=None, msg=None, slot_id=101):
        """Wrapper for sending large message (larger than 58 bytes) in batch in a transparent way."""
        if not msg:
            raise Exception("Missing msg")

        # Split the payload in multiple chunks
        chunks = [payload[x:x+MAX_LARGE_PAYLOAD_SIZE-1] for x in range(0, len(payload), 57)]
        for chunk in chunks:
            # print chunk
            # print [ord(c) for c in chunk]
            current_payload = [slot_id, 255]  # 255 means that it's not the last payload
            # If it's less than the max size, set explicitely the size
            if len(chunk) < 57:
                current_payload = [slot_id, len(chunk)]

            # Append the actual payload
            if isinstance(chunk, list):
	               current_payload.extend(chunk)
            else:
                for c in chunk:
                    current_payload.append(c)

            self.send_message(payload=current_payload, msg=msg)
        return

    def read_bytes(self, n=64, to_bytes=False, timeout_ms=100):
        """Read n bytes and return an array of uint8 (int)."""
        out = self._hid.read(n, timeout_ms=timeout_ms)
        logging.debug('read="%s"', ''.join([chr(c) for c in out]))
        outstr = bytearray(out)
        logging.debug('outstring="%s"', outstr)
        if outstr.decode(errors="ignore").find("UNINITIALIZED") != -1:
            raise RuntimeError('No PIN set, You must set a PIN first')
        elif outstr.decode(errors="ignore").find("INITIALIZED") != -1:
            raise RuntimeError('OnlyKey is locked, enter PIN to unlock')
        elif outstr.decode(errors="ignore").find(KnownResponse.WRONG_CHALLENGE.value) != -1:
            raise RuntimeError(KnownResponse.WRONG_CHALLENGE.value)
        # The device used to call all three of these a wrong challenge. A late
        # press and a press-mode rejection are now named separately, and they
        # are not the same advice: one means press sooner, one means the key
        # did not take the press at all, and only the first means the digits
        # were wrong. Raised verbatim, like every other line here, so the
        # device's own words reach the caller.
        elif outstr.decode(errors="ignore").find(KnownResponse.CONFIRMATION_WINDOW_CLOSED.value) != -1:
            raise RuntimeError(KnownResponse.CONFIRMATION_WINDOW_CLOSED.value)
        elif outstr.decode(errors="ignore").find(KnownResponse.PRESS_NOT_ACCEPTED.value) != -1:
            raise RuntimeError(KnownResponse.PRESS_NOT_ACCEPTED.value)
        elif outstr.decode(errors="ignore").find("No PIN set, You must set a PIN first") != -1:
            raise RuntimeError('Error OnlyKey must be configured first')
        elif outstr.decode(errors="ignore").find("Timeout occured while waiting for confirmation on OnlyKey") != -1:
            raise RuntimeError('Timeout occured while waiting for confirmation on OnlyKey')
        elif outstr.decode(errors="ignore").find("Error key not set as signature key") != -1:
            raise RuntimeError('Error key not set as signature key')
        elif outstr.decode(errors="ignore").find("Error key not set as decryption key") != -1:
            raise RuntimeError('Error key not set as decryption key')
        elif outstr.decode(errors="ignore").find("Error with RSA data to sign invalid size") != -1:
            raise RuntimeError('Error with RSA data to sign invalid size')
        elif outstr.decode(errors="ignore").find("Error with RSA signing") != -1:
            raise RuntimeError('Error with RSA signing')
        elif outstr.decode(errors="ignore").find("Error with RSA data to decrypt invalid size") != -1:
            raise RuntimeError('Error with RSA data to decrypt invalid size')
        elif outstr.decode(errors="ignore").find("Error with RSA decryption") != -1:
            raise RuntimeError('Error with RSA decryption')
        elif outstr.decode(errors="ignore").find("Error no key set in this slot") != -1:
            raise RuntimeError('Error no key set in this slot')

        if to_bytes:
            # Returns the bytes a string if requested
            return bytes(out)

        # Returns the raw list
        return out

    def read_string(self, timeout_ms=100):
        """Read an ASCII string."""
        return ''.join([chr(item) for item in self.read_bytes(MAX_INPUT_REPORT_SIZE, timeout_ms=timeout_ms) if item != 0])


    def read_chunk(self, timeout_ms=100):
        return self.read_bytes(MAX_INPUT_REPORT_SIZE, timeout_ms=timeout_ms)

    def getlabels(self):
        """Fetch the list of `Slot` from the OnlyKey.

        No need to read messages.
        """
        self.send_message(msg=Message.OKGETLABELS)
        time.sleep(0.5)
        slots = []
        for _ in range(12):
            data = self.read_string().split('|')
            slot_number = ord(data[0])
            if slot_number >= 16:
                slot_number = slot_number - 6
            if 1 <= slot_number <= 12:
                slots.append(Slot(slot_number, label=data[1]))
        return slots

    def getduolabels(self):
        """Fetch the list of `Slot` from the OnlyKey.

        No need to read messages.
        """
        self.send_message(msg=Message.OKGETLABELS)
        time.sleep(0.5)
        slots = []
        for _ in range(24):
            data = self.read_string().split('|')
            # A device with fewer labels than the loop count stops answering,
            # and read_string() returns ''. ord('') is a TypeError, so the
            # command died rather than finishing with the labels it had:
            #   TypeError: ord() expected a character, but string of length 0
            # Nothing here needs all 24 - the loop is an upper bound.
            if not data[0]:
                break
            slot_number = ord(data[0])
            if slot_number >= 16:
                slot_number = slot_number - 6
            if 1 <= slot_number <= 24:
                slots.append(Slotduo(slot_number, label=data[1]))
        return slots

    def getkeylabels(self):
        """Fetch the list of `Keys` from the OnlyKey.

        No need to read messages.
        """
        self.send_message(msg=Message.OKGETLABELS, slot_id=107)
        time.sleep(0)
        slots = []
        for _ in range(20):
            data = self.read_string().split('|')
            if not data[0]:   # see getduolabels() above - same empty-read guard
                break
            slot_number = ord(data[0])
            if 25 <= slot_number <= 44:
                slots.append(Slot(slot_number, label=data[1]))

        return slots

    def getcapabilities(self):
        """Ask the firmware what it supports (OKGETLABELS with selector 'c').

        Returns the dict from onlykey.protocol.parse_capabilities, or None on
        firmware that predates the capabilities report (it answers with slot
        labels instead, which are drained here so the next read is clean)."""
        self.send_message(msg=Message.OKGETLABELS, payload=[CAPABILITIES_SELECTOR[0]])
        time.sleep(0.2)
        first = self.read_bytes(MAX_INPUT_REPORT_SIZE, timeout_ms=500)
        caps = parse_capabilities(first)
        if caps is None:
            for _ in range(12):  # old firmware: drain the slot-label reply
                if not self.read_bytes(MAX_INPUT_REPORT_SIZE, timeout_ms=100):
                    break
        return caps

    def is_duo(self):
        """True for an OnlyKey DUO. Uses the capabilities report (firmware
        3.1.0+); older firmware falls back to the version-string suffix
        (\'c\' = Color/original, \'d\' = DUO)."""
        caps = self.getcapabilities()
        if caps is not None:
            return CapabilityFlag.DUO in caps['flags']
        self.set_time(time.time())
        version = self.read_string()
        return not version.rstrip().endswith('c')

    def displaycapabilities(self):
        caps = self.getcapabilities()
        if caps is None:
            print('Firmware does not report capabilities (older than protocol v1)')
            return
        print('firmware      ', caps['version'])
        print('protocol      ', caps['protocol_version'])
        print('key types     ', ' '.join(k.name for k in caps['key_types']))
        print('flags         ', ' '.join(f.name for f in caps['flags']) or '-')
        for field, modes in caps['user_input_modes'].items():
            print('%-14s' % field.lower(), ' '.join(m.name.lower() for m in modes))

    def displaykeylabels(self):
        global slot
        time.sleep(2)

        self.read_string(timeout_ms=100)
        empty = 'a'
        while not empty:
            empty = self.read_string(timeout_ms=100)

        time.sleep(1)
        print('You should see your OnlyKey blink 3 times')
        print()

        tmp = {}
        for slot in self.getkeylabels():
            tmp[slot.name] = slot
        slots = iter(['RSA Key 1', 'RSA Key 2', 'RSA Key 3', 'RSA Key 4', 'ECC Key 1', 'ECC Key 2', 'ECC Key 3', 'ECC Key 4', 'ECC Key 5', 'ECC Key 6', 'ECC Key 7', 'ECC Key 8', 'ECC Key 9', 'ECC Key 10', 'ECC Key 11', 'ECC Key 12', 'ECC Key 13', 'ECC Key 14', 'ECC Key 15', 'ECC Key 16', 'ECC Key 17', 'ECC Key 18', 'ECC Key 19', 'ECC Key 20', 'ECC Key 21', 'ECC Key 22', 'ECC Key 23', 'ECC Key 24', 'ECC Key 25', 'ECC Key 26', 'ECC Key 27', 'ECC Key 28', 'ECC Key 29'])
        for slot_name in slots:
            print(tmp[slot_name].to_str())

    def setslot(self, slot_number, message_field, value):
        """Set a slot field to the given value."""
        self.send_message(msg=Message.OKSETSLOT, slot_id=slot_number, message_field=message_field, payload=value, from_ascii=True)
        print(self.read_string())

    def wipeslot(self, slot_number):
        """Wipe all the fields for the given slot."""
        self.send_message(msg=Message.OKWIPESLOT, slot_id=slot_number)
        for _ in range(8):
            print(self.read_string())

    def setkey(self, slot_number, key_type, key_features, value):
        # slot 131-132 Reserved
        # slot 129-130 HMAC Keys
        # slot 101-116 ECC Keys
        # slot 1-4 RSA Keys (also composite PQC PGP keys - see 'p' below)
        #
        # 'p' is a composite PQC PGP key and takes a different road out of this
        # function. It lives in an RSA slot, but its 160-byte seed blob is
        # chunked 57/57/46 with a fixed type byte rather than sliced into the
        # 114-char pieces the RSA branches below use, and - unlike everything
        # else here - the device's acknowledgement is READ rather than printed.
        # That matters: OKSETPRIV is refused outside config mode, and a
        # composite key cannot be read back afterwards (okcrypto_getpubkey()
        # has no KEYTYPE_PQC_PGP branch), so an unchecked reply means a stored
        # key and an empty slot look identical. load_composite_key() raises
        # instead.
        if key_type == 'p':
            from . import pqc
            if key_features:
                raise ValueError(
                    "composite PQC PGP keys take no feature letter - they are "
                    "always decrypt and sign (type byte 0x%02x), fixed by what "
                    "the algorithm is. Use: setkey PQC<1-4> p <%d hex chars>"
                    % (pqc.PQC_KEY_TYPE_BYTE, pqc.PQC_PGP_BLOB_LEN * 2))
            try:
                blob = bytes.fromhex(value.strip())
            except ValueError:
                raise ValueError(
                    "composite PQC PGP key must be %d hex characters "
                    "(a %d-byte seed blob)"
                    % (pqc.PQC_PGP_BLOB_LEN * 2, pqc.PQC_PGP_BLOB_LEN))
            # Slot range and blob length are checked inside, and the device's
            # acknowledgement is read there - so reaching the next line means
            # the load happened. Say so: this branch returns before setkey()'s
            # own print(self.read_string()) at the bottom, so without this a
            # successful load produced NO OUTPUT AT ALL, which is exactly the
            # silent-success shape this file has been fixing elsewhere.
            pqc.load_composite_key(self, slot_number, blob)
            print('Loaded composite PQC PGP key (%d bytes) into PQC%d'
                  % (len(blob), slot_number))
            return
        # set key type + features from the shared CLI letter tables
        # (setkey <slot> <x|n|s|c|m|w|h> <d|s|b> <hex>); a numeric key_type is
        # passed through. The tables come from the generated protocol module,
        # which is why this is eight lines instead of the old if/elif ladder.
        if key_type in CLI_KEY_LETTERS:
            key_type = int(CLI_KEY_LETTERS[key_type])
        else:
            key_type = int(key_type)
        # An unrecognised feature letter is an ERROR, not zero flags.
        # key_type |= CLI_KEY_FEATURES.get(key_features, 0) silently dropped
        # the flags on a typo, producing a key the device would not use for
        # the operation it was loaded for - and, because the bare type is
        # below 16, an odd-length payload on the wire behind it.
        if key_features:
            if key_features not in CLI_KEY_FEATURES:
                raise ValueError(
                    "key_features must be '' or one of 'd' (decrypt), "
                    "'s' (sign), 'b' (backup); got %r" % (key_features,))
            key_type |= int(CLI_KEY_FEATURES[key_features])
        logging.debug('SETTING KEY IN SLOT:', slot_number)
        logging.debug('TO TYPE:', key_type)
        logging.debug('KEY:', value)
        if slot_number >= 1 and slot_number <= 4:
            if key_type & 0xf == 2: # RSA 2048
                self.send_message(msg=Message.OKSETPRIV, slot_id=slot_number, payload=format(key_type, '02x')+value[:114])
                self.send_message(msg=Message.OKSETPRIV, slot_id=slot_number, payload=format(key_type, '02x')+value[114:228])
                self.send_message(msg=Message.OKSETPRIV, slot_id=slot_number, payload=format(key_type, '02x')+value[228:342])
                self.send_message(msg=Message.OKSETPRIV, slot_id=slot_number, payload=format(key_type, '02x')+value[342:456])
                self.send_message(msg=Message.OKSETPRIV, slot_id=slot_number, payload=format(key_type, '02x')+value[456:512])
            elif key_type & 0xf == 4: # RSA 4096
                self.send_message(msg=Message.OKSETPRIV, slot_id=slot_number, payload=format(key_type, '02x')+value[:114])
                self.send_message(msg=Message.OKSETPRIV, slot_id=slot_number, payload=format(key_type, '02x')+value[114:228])
                self.send_message(msg=Message.OKSETPRIV, slot_id=slot_number, payload=format(key_type, '02x')+value[228:342])
                self.send_message(msg=Message.OKSETPRIV, slot_id=slot_number, payload=format(key_type, '02x')+value[342:456])
                self.send_message(msg=Message.OKSETPRIV, slot_id=slot_number, payload=format(key_type, '02x')+value[456:570])
                self.send_message(msg=Message.OKSETPRIV, slot_id=slot_number, payload=format(key_type, '02x')+value[570:684])
                self.send_message(msg=Message.OKSETPRIV, slot_id=slot_number, payload=format(key_type, '02x')+value[684:798])
                self.send_message(msg=Message.OKSETPRIV, slot_id=slot_number, payload=format(key_type, '02x')+value[798:912])
                self.send_message(msg=Message.OKSETPRIV, slot_id=slot_number, payload=format(key_type, '02x')+value[912:1024])
            else:
                # The `else` below belongs to the SLOT test, not to these two
                # branches, so an RSA slot carrying any other key type used to
                # fall out of setkey() having sent NOTHING - and then sleep a
                # second and print the device's empty read, which looks exactly
                # like a quiet success. `setkey RSA1 7 d <blob>` reported
                # nothing wrong and loaded nothing.
                #
                # RSA slots take 2048 and 4096 here and nothing else. A
                # composite PQC key also lives in an RSA slot, but its 160-byte
                # blob is chunked by pqc.load_composite_key() rather than by
                # this function, and `loadpqc` is the only way in.
                raise ValueError(
                    "RSA slots take key type 2 (RSA-2048) or 4 (RSA-4096); "
                    "got %d. A composite PQC PGP key loads with "
                    "`onlykey-cli loadpqc <keyfile> PQC%d`."
                    % (key_type & 0xf, slot_number))
        else:
            self.send_message(msg=Message.OKSETPRIV, slot_id=slot_number, payload=format(key_type, '02x')+value)
        time.sleep(1)
        print(self.read_string())

    def wipekey(self, slot_number):
        logging.debug('WIPING KEY IN SLOT:', slot_number)
        self.send_message(msg=Message.OKWIPEPRIV, slot_id=slot_number, payload='00')
        time.sleep(1)
        result = self.read_string()
        print(result)
        # The label clear below is an OKSETSLOT, which is not gated on config
        # mode - so after a REFUSED wipe it still succeeded, the key stayed on
        # the device without its label, and the last line printed was
        # "Successfully set Label", which reads as though the wipe happened.
        # Only clear the label of a key that was actually wiped.
        if is_error(result.encode("latin-1", "replace")):
            return
        if slot_number > 100:
            self.send_message(msg=Message.OKSETSLOT, slot_id=slot_number-100+28, message_field=MessageField.LABEL, payload="", from_ascii=True)
        elif slot_number > 0:
            self.send_message(msg=Message.OKSETSLOT, slot_id=slot_number+24, message_field=MessageField.LABEL, payload="", from_ascii=True)
        time.sleep(1)
        print(self.read_string())

    def slot(self, slot):
        global slotnum
        slotnum = slot

    def loadkey(self, key_ascii_armor, passphrase, slot=99, key_features=''):
        """Load an OpenPGP private key (RSA or ECC) onto the OnlyKey.

        Parses the PGP armored key, extracts private key material (p/q for RSA,
        s for ECC), and sends it to the device. Mirrors the OnlyKey App's RSA/ECC
        key loading functionality.

        Args:
            key_ascii_armor: ASCII-armored PGP private key string
            passphrase: Passphrase to decrypt the PGP key
            slot: Key slot number (1-4 for RSA, 101-116 for ECC, or 99 for auto)
            key_features: 'd' for decryption, 's' for signing, 'b' for backup
        """
        from . import pgp_bridge
        parsed = pgp_bridge.parse_armored(key_ascii_armor, passphrase)
        if parsed.get('type') == 'pqc-composite':
            raise RuntimeError(
                'This is a composite PQC PGP key. Load it with '
                '`onlykey-cli loadpqc <keyfile> RSA1` (it goes into an RSA slot as a '
                '160-byte seed), not loadkey.')
        keys = []
        is_ecc = (parsed.get('type') == 'ecc')
        ecc_curve = 0
        for k in parsed.get('keys', []):
            if k.get('kind') == 'rsa':
                keys.append({'name': k['name'],
                             'p': binascii.unhexlify(k['p']),
                             'q': binascii.unhexlify(k['q'])})
            else:
                if not ecc_curve:
                    ecc_curve = k.get('curve', 0)
                keys.append({'name': k['name'], 's': binascii.unhexlify(k['s'])})
        return self._load_parsed_keys(keys, is_ecc, ecc_curve, slot, key_features)

    def _long_to_bytes(self, n):
        """Convert a long integer to a byte string."""
        h = '%x' % n
        s = binascii.unhexlify(('0' * (len(h) % 2) + h))
        return s

    def _load_parsed_keys(self, keys, is_ecc, ecc_curve, slot, key_features):
        """Load key material already parsed by pgp_bridge (OpenPGP.js) onto the OnlyKey.

        keys: list of {'name', 'p','q' (RSA, bytes)} or {'name', 's' (ECC, bytes)}.
        """

        if not keys:
            raise RuntimeError('No keys found in PGP key')

        print('Found {} key(s):'.format(len(keys)))
        for i, k in enumerate(keys):
            if 'p' in k:
                key_size = (len(k['p']) + len(k['q'])) * 8
                print('  [{}] {} - RSA {} bits'.format(i, k['name'], key_size))
            else:
                print('  [{}] {} - ECC {} bytes'.format(i, k['name'], len(k['s'])))

        if slot == 99:
            # Auto-assign: Slot 99 mode from OnlyKey App
            # If 2+ subkeys: subkey 1 = decryption (slot 1), subkey 2 = signing (slot 2)
            # If 1 subkey: subkey 1 = decryption (slot 1), primary = signing (slot 2)
            # ECC slots start at 101
            if len(keys) >= 3:
                signing_key = keys[2]
            else:
                signing_key = keys[0]

            decryption_key = keys[1] if len(keys) > 1 else None

            # Load signing key
            self._load_single_key(signing_key, 2, 's', is_ecc, ecc_curve)
            # Load decryption key
            if decryption_key:
                self._load_single_key(decryption_key, 1, 'd', is_ecc, ecc_curve)
        else:
            # Load single key to specified slot
            if len(keys) == 1:
                self._load_single_key(keys[0], slot, key_features, is_ecc, ecc_curve)
            else:
                print('Multiple keys found. Loading primary key to slot {}.'.format(slot))
                self._load_single_key(keys[0], slot, key_features, is_ecc, ecc_curve)

    def _load_single_key(self, key_obj, slot, key_features, is_ecc=False, ecc_curve=0):
        """Load a single key (RSA or ECC) onto the OnlyKey device."""
        if 's' in key_obj:
            # ECC key
            key_data = key_obj['s']
            if len(key_data) != 32:
                raise RuntimeError('ECC key must be 32 bytes, got {}'.format(len(key_data)))

            key_type_num = ecc_curve
            if key_features == 'd':
                key_type_num += 32
            elif key_features == 's':
                key_type_num += 64
            elif key_features == 'b':
                key_type_num += 32 + 128

            if slot < 101:
                slot += 100

            hex_key = binascii.hexlify(key_data).decode('ascii')
            print('Loading ECC key to slot {}...'.format(slot))
            self.send_message(msg=Message.OKSETPRIV, slot_id=slot,
                            payload=format(key_type_num, 'x') + hex_key)
            time.sleep(1)
            print(self.read_string())
        else:
            # RSA key
            p_bytes = key_obj['p']
            q_bytes = key_obj['q']
            key_data = p_bytes + q_bytes
            key_size = len(key_data)

            # Determine RSA type from key size: p+q combined
            # 1024-bit: p+q = 128 bytes, type 1
            # 2048-bit: p+q = 256 bytes, type 2
            # 3072-bit: p+q = 384 bytes, type 3
            # 4096-bit: p+q = 512 bytes, type 4
            rsa_type = key_size // 128
            if rsa_type not in [1, 2, 3, 4]:
                raise RuntimeError('Unsupported RSA key size: {} bytes (p+q). Expected 1024, 2048, 3072, or 4096 bit key.'.format(key_size))

            key_type_num = rsa_type
            if key_features == 'd':
                key_type_num += 32
            elif key_features == 's':
                key_type_num += 64
            elif key_features == 'b':
                key_type_num += 32 + 128

            if slot > 4:
                slot = 1  # Default RSA slot

            hex_key = binascii.hexlify(key_data).decode('ascii')
            print('Loading RSA {} key to slot {}...'.format(rsa_type * 1024, slot))
            self.setkey(slot, str(rsa_type), key_features if key_features else 'd', hex_key)

    def restore_from_backup(self, backup_data):
        """Restore the OnlyKey from a backup file.

        Parses the OnlyKey backup file format, verifies the SHA256 hash,
        and sends the restore data to the device in 57-byte chunks.

        Args:
            backup_data: String contents of the backup file
        """
        # Parse backup data - convert base64 lines to hex
        hex_data = self._parse_backup_data(backup_data)
        if not hex_data:
            raise RuntimeError('No valid backup data found')

        print('Sending restore data to OnlyKey ({} bytes)...'.format(len(hex_data) // 2))

        # Send in 57-byte (114 hex char) chunks
        max_packet_size = 114  # 57 byte pairs
        offset = 0
        packet_num = 0
        while offset < len(hex_data):
            chunk = hex_data[offset:offset + max_packet_size]
            remaining = len(hex_data) - offset
            is_final = remaining <= max_packet_size

            if is_final:
                # Final packet: header is the number of bytes in this chunk
                packet_header = format(len(chunk) // 2, '02x')
            else:
                # Non-final packet: header is FF
                packet_header = 'FF'

            # Build payload: [packet_header_byte] + [data_bytes]
            payload = packet_header + chunk
            self.send_message(msg=Message.OKRESTORE, payload=payload)
            offset += max_packet_size
            packet_num += 1

        print('Restore data sent ({} packets). Please wait for OnlyKey to process...'.format(packet_num))
        time.sleep(2)
        # Try to read response
        try:
            resp = self.read_string(timeout_ms=10000)
            if resp:
                print(resp)
        except:
            pass

    def _parse_backup_data(self, contents):
        """Parse OnlyKey backup file format.

        The backup file format is:
            -----BEGIN ONLYKEY BACKUP-----
            <base64 data line 1>
            <base64 data line 2>
            ...
            --<base64 encoded SHA256 hash>
            -----END ONLYKEY BACKUP-----

        Returns: hex string of all backup data concatenated
        """
        import base64 as b64

        hex_parts = []
        backup_hash = bytearray(32)  # Running SHA256 hash for verification
        stored_hash = None

        for line in contents.strip().split('\n'):
            line = line.strip()
            if not line:
                continue
            if line.startswith('-----'):
                continue
            if line.startswith('--') and not line.startswith('-----'):
                # This is the hash line: --<base64 encoded hash>
                hash_b64 = line[2:]
                try:
                    stored_hash = binascii.hexlify(b64.b64decode(hash_b64)).decode('ascii').upper()
                except:
                    pass
                continue

            # Regular data line - decode from base64 to hex
            try:
                decoded = b64.b64decode(line)
                hex_line = binascii.hexlify(decoded).decode('ascii').upper()
                hex_parts.append(hex_line)

                # Update running hash
                h = hashlib.sha256()
                h.update(backup_hash)
                h.update(decoded)
                backup_hash = bytearray(h.digest())
            except Exception as e:
                logging.warning('Failed to decode backup line: {}'.format(e))
                continue

        if stored_hash:
            computed_hash = binascii.hexlify(backup_hash).decode('ascii').upper()
            if computed_hash == stored_hash:
                print('Backup file SHA256 hash verified successfully')
            else:
                print('WARNING: Backup file hash mismatch!')
                print('  Expected: {}'.format(stored_hash))
                print('  Computed: {}'.format(computed_hash))
                raise RuntimeError('Backup file is corrupt - SHA256 hash mismatch')

        return ''.join(hex_parts)

    def set_backup_passphrase(self, passphrase):
        """Set the backup passphrase on the OnlyKey.

        The passphrase is hashed with SHA256 and stored as the backup
        encryption key on slot 131.

        Args:
            passphrase: Backup passphrase string (must be >= 25 characters)
        """
        if len(passphrase) < 25:
            raise RuntimeError('Backup passphrase must be at least 25 characters')

        # SHA256 hash of passphrase = 32-byte backup key
        key = hashlib.sha256(passphrase.encode('utf-8')).digest()
        hex_key = binascii.hexlify(key).decode('ascii')

        # type 161 = 128 (backup) + 32 (decryption) + 1 = Backup Decryption Key
        key_type = 161
        slot = 131

        print('Setting backup passphrase...')
        self.send_message(msg=Message.OKSETPRIV, slot_id=slot,
                         payload=format(key_type, '02x') + hex_key)
        time.sleep(1)
        print(self.read_string())

    def load_firmware(self, firmware_data):
        """Load firmware onto the OnlyKey device.

        Parses a signed firmware file, transitions the device to bootloader
        mode if needed, and sends firmware blocks with signature verification.
        Mirrors the OnlyKey App's firmware update functionality.

        The firmware file format is:
            -----BEGIN SIGNED FIRMWARE-----
            <block 1: 64-char signature + 1-char info + 64-char next signature + data>
            <block 2: ...>
            ...
            -----END SIGNED FIRMWARE-----

        Args:
            firmware_data: String contents of the signed firmware file
        """
        # Parse the firmware file
        blocks = self._parse_firmware_data(firmware_data)
        if not blocks:
            raise RuntimeError('No valid firmware data found')

        print('Parsed firmware file: {} blocks'.format(len(blocks)))

        # Check if device is in bootloader mode by reading its state
        # Send initial dummy packet to kick device from config mode into bootloader
        print('Requesting bootloader mode...')
        self._send_firmware_chunk('1234', 'FF')

        # Wait for device response
        time.sleep(1)
        resp = ''
        for _ in range(20):
            try:
                resp = self.read_string(timeout_ms=500)
                if resp:
                    print('Device: {}'.format(resp))
                    if 'BOOTLOADER' in resp:
                        break
                    elif 'ERROR' in resp:
                        raise RuntimeError('Device error: {}'.format(resp))
                    elif 'FW LOAD REQUEST' in resp or 'REBOOTING' in resp:
                        print('Device is rebooting into bootloader, please wait...')
                        time.sleep(3)
                        # Reconnect to device after reboot
                        self._reconnect_for_firmware()
                        break
            except RuntimeError as e:
                if 'locked' in str(e).lower() or 'PIN' in str(e):
                    raise
            except:
                pass
            time.sleep(0.5)

        # Now send firmware blocks
        print('Loading firmware...')
        for i, block in enumerate(blocks):
            pct = int((i / len(blocks)) * 100)
            print('\r  {} percent complete - block {}/{}...'.format(pct, i + 1, len(blocks)), end='', flush=True)

            # Send this block in 57-byte (114 hex char) chunks
            self._submit_firmware_block(block)

            # Wait for device acknowledgment
            if i < len(blocks) - 1:
                # Intermediate block - wait for "NEXT BLOCK"
                ack = self._wait_for_firmware_ack('NEXT BLOCK', timeout=10)
                if not ack:
                    raise RuntimeError('Device did not acknowledge block {}. Firmware update failed.'.format(i + 1))
            else:
                # Final block - wait for "SUCCESSFULLY LOADED FW"
                ack = self._wait_for_firmware_ack('SUCCESSFULLY LOADED FW', timeout=15)
                if not ack:
                    raise RuntimeError('Device did not confirm firmware load completion.')

        print('\r  100 percent complete - all {} blocks sent.'.format(len(blocks)))
        print('Firmware loaded successfully! Device will reboot.')

    def _parse_firmware_data(self, contents):
        """Parse a signed firmware file into blocks.

        Returns: list of block strings (hex data lines)
        """
        lines = contents.strip().split('\n')
        blocks = []
        for line in lines:
            line = line.strip()
            if line.startswith('-----'):
                continue
            if not line:
                continue
            blocks.append(line)
        return blocks

    def _send_firmware_chunk(self, hex_data, packet_header):
        """Send a single firmware chunk via OKFWUPDATE message.

        Args:
            hex_data: hex string of data to send
            packet_header: hex byte header ('FF' for non-final, or byte count for final)
        """
        payload = packet_header + hex_data
        self.send_message(msg=Message.OKFWUPDATE, payload=payload)

    def _submit_firmware_block(self, block_data):
        """Send a single firmware block in 57-byte chunks, waiting for ack between chunks.

        Args:
            block_data: hex string of the full block to send
        """
        max_packet_size = 114  # 57 byte pairs
        offset = 0

        while offset < len(block_data):
            chunk = block_data[offset:offset + max_packet_size]
            remaining = len(block_data) - offset
            is_final = remaining <= max_packet_size

            if is_final:
                packet_header = format(len(chunk) // 2, '02x').upper()
            else:
                packet_header = 'FF'

            self._send_firmware_chunk(chunk, packet_header)

            # Wait for device to acknowledge each chunk
            if not is_final:
                ack = self._wait_for_firmware_ack('RECEIVED OKFWUPDATE', timeout=5)
                if not ack:
                    raise RuntimeError('Device did not acknowledge firmware chunk')

            offset += max_packet_size

    def _wait_for_firmware_ack(self, expected_msg, timeout=5):
        """Wait for a specific firmware acknowledgment message from the device.

        Args:
            expected_msg: string to look for in device response
            timeout: max seconds to wait

        Returns: True if expected message received, False otherwise
        """
        start = time.time()
        while time.time() - start < timeout:
            try:
                resp = self.read_string(timeout_ms=500)
                if resp:
                    logging.debug('FW ack: %s', resp)
                    if expected_msg in resp:
                        return True
                    elif 'ERROR' in resp:
                        print('\nDevice error: {}'.format(resp))
                        return False
                    elif 'UNLOCKED' in resp or '|' in resp:
                        # Unexpected message, keep waiting
                        continue
            except:
                pass
        return False

    def _reconnect_for_firmware(self):
        """Reconnect to the OnlyKey after it reboots into bootloader mode."""
        print('Waiting for device to reconnect in bootloader mode...')
        self._hid.close()
        time.sleep(5)

        # Try to reconnect
        for attempt in range(10):
            try:
                self._hid.open()
                resp = self.read_string(timeout_ms=1000)
                if resp:
                    print('Device: {}'.format(resp))
                    if 'BOOTLOADER' in resp:
                        print('Device is now in bootloader mode')
                        return
                time.sleep(1)
            except:
                time.sleep(2)

        raise RuntimeError('Could not reconnect to device in bootloader mode. '
                         'Please manually reconnect and try again.')

    def loadprivate(self, rootkey_ascii_armor, rootkey_passphrase):
        """Legacy method - parse and display private keys from OpenPGP keys.

        For actually loading keys onto the device, use loadkey() instead.
        Parses via the OpenPGP.js bridge (pgp_bridge); handles RSA, ECC, and
        composite PQC keys.
        """
        from . import pgp_bridge
        parsed = pgp_bridge.parse_armored(rootkey_ascii_armor, rootkey_passphrase)
        print('key type:', parsed.get('type'))
        if parsed.get('type') == 'pqc-composite':
            print('composite PQC blob (160B):', parsed['blob'])
            return
        for k in parsed.get('keys', []):
            if k.get('kind') == 'rsa':
                print(k['name'], 'RSA  p||q =', k['p'] + k['q'])
            else:
                print(k['name'], 'ECC  s =', k['s'], ' curve =', k.get('curve'))

    def encrypt(self, slot):
        print('Unavailable command')

    def decrypt(self, slot):
        print('Unavailable command')

    def sign(self, slot):
        print('Unavailable command')

    def verify(self, slot):
        print('Unavailable command')