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


class Message(Enum):
    OKSETPIN = 225  # 0xE1
    OKSETSDPIN = 226  # 0xE2
    OKSETPDPIN = 227  # 0xE3
    OKSETTIME = 228  # 0xE4
    OKGETLABELS = 229  # 0xE5
    OKSETSLOT = 230  # 0xE6
    OKWIPESLOT = 231  # 0xE7
    OKSETU2FPRIV = 232  # 0xE8
    OKWIPEU2FPRIV = 233  # 0xE9
    OKSETU2FCERT = 234  # 0xEA
    OKWIPEU2FCERT = 235  # 0xEB
    OKGETPUBKEY = 236
    OKSIGN = 237
    OKWIPEPRIV = 238
    OKSETPRIV = 239
    OKDECRYPT = 240
    OKRESTORE = 241


class MessageField(Enum):
    LABEL = 1
    URL = 15
    DELAY1 = 17
    NEXTKEY4 = 18
    USERNAME = 2
    NEXTKEY1 = 16
    NEXTKEY2 = 3
    DELAY2 = 4
    PASSWORD = 5
    NEXTKEY3 = 6
    DELAY3 = 7
    NEXTKEY5 = 19
    TFATYPE = 8
    TOTPKEY = 9
    YUBIAUTH = 10
    IDLETIMEOUT = 11
    WIPEMODE = 12
    KEYTYPESPEED = 13
    KEYLAYOUT = 14
    LEDBRIGHTNESS = 24
    LOCKBUTTON = 25
    HMACMODE = 26
    SYSADMINMODE = 27
    SECPROFILEMODE = 23
    PGPCHALENGEMODE = 22
    SSHCHALENGEMODE = 21
    BACKUPMODE = 20
    TOUCHSENSE = 28

class KeyTypeEnum(Enum):
    ED22519 = 1
    P256 = 2
    SECP256K1 = 3
    CURVE25519 = 4
    MLKEM768 = 5
    XWING = 6

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
        elif outstr.decode(errors="ignore").find("Error incorrect challenge was entered") != -1:
            raise RuntimeError('Error incorrect challenge was entered')
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
            slot_number = ord(data[0])
            if 25 <= slot_number <= 44:
                slots.append(Slot(slot_number, label=data[1]))

        return slots

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
        # slot 1-4 RSA Keys
        # set key type
        if key_type == 'x':
            key_type = '1'
        elif key_type == 'n':
            key_type = '2'
        elif key_type == 's':
            key_type = '3'
        elif key_type == 'm':
            key_type = '5'
        elif key_type == 'w':
            key_type = '6'
        elif key_type == 'h':
            key_type = '9'
        # set key features
        if key_features == 'd':
            key_type = int(key_type) + 32 # Decrypt flag
        elif key_features == 's':
            key_type = int(key_type) + 64 # Sign flag
        elif key_features == 'b':
            key_type = int(key_type) + 32 # Decrypt flag
            key_type = int(key_type) + 128 # Backup flag
        else:
            key_type = int(key_type)
        logging.debug('SETTING KEY IN SLOT:', slot_number)
        logging.debug('TO TYPE:', key_type)
        logging.debug('KEY:', value)
        if slot_number >= 1 and slot_number <= 4:
            if key_type & 0xf == 2: # RSA 2048
                self.send_message(msg=Message.OKSETPRIV, slot_id=slot_number, payload=format(key_type, 'x')+value[:114])
                self.send_message(msg=Message.OKSETPRIV, slot_id=slot_number, payload=format(key_type, 'x')+value[114:228])
                self.send_message(msg=Message.OKSETPRIV, slot_id=slot_number, payload=format(key_type, 'x')+value[228:342])
                self.send_message(msg=Message.OKSETPRIV, slot_id=slot_number, payload=format(key_type, 'x')+value[342:456])
                self.send_message(msg=Message.OKSETPRIV, slot_id=slot_number, payload=format(key_type, 'x')+value[456:512])
            elif key_type & 0xf == 4: # RSA 4096
                self.send_message(msg=Message.OKSETPRIV, slot_id=slot_number, payload=format(key_type, 'x')+value[:114])
                self.send_message(msg=Message.OKSETPRIV, slot_id=slot_number, payload=format(key_type, 'x')+value[114:228])
                self.send_message(msg=Message.OKSETPRIV, slot_id=slot_number, payload=format(key_type, 'x')+value[228:342])
                self.send_message(msg=Message.OKSETPRIV, slot_id=slot_number, payload=format(key_type, 'x')+value[342:456])
                self.send_message(msg=Message.OKSETPRIV, slot_id=slot_number, payload=format(key_type, 'x')+value[456:570])
                self.send_message(msg=Message.OKSETPRIV, slot_id=slot_number, payload=format(key_type, 'x')+value[570:684])
                self.send_message(msg=Message.OKSETPRIV, slot_id=slot_number, payload=format(key_type, 'x')+value[684:798])
                self.send_message(msg=Message.OKSETPRIV, slot_id=slot_number, payload=format(key_type, 'x')+value[798:912])
                self.send_message(msg=Message.OKSETPRIV, slot_id=slot_number, payload=format(key_type, 'x')+value[912:1024])
        else:
            self.send_message(msg=Message.OKSETPRIV, slot_id=slot_number, payload=format(key_type, 'x')+value)
        time.sleep(1)
        print(self.read_string())

    def wipekey(self, slot_number):
        logging.debug('WIPING KEY IN SLOT:', slot_number)
        self.send_message(msg=Message.OKWIPEPRIV, slot_id=slot_number, payload='00')
        time.sleep(1)
        print(self.read_string())
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
        try:
            import pgpy
        except ImportError:
            raise RuntimeError('pgpy is required for loading PGP keys. Install with: pip install pgpy')

        (rootkey, _) = pgpy.PGPKey.from_blob(key_ascii_armor)

        if rootkey.is_protected:
            try:
                with rootkey.unlock(passphrase):
                    return self._process_pgp_key(rootkey, slot, key_features)
            except Exception as e:
                raise RuntimeError('Failed to unlock PGP key: {}'.format(str(e)))
        else:
            return self._process_pgp_key(rootkey, slot, key_features)

    def _long_to_bytes(self, n):
        """Convert a long integer to a byte string."""
        h = '%x' % n
        s = binascii.unhexlify(('0' * (len(h) % 2) + h))
        return s

    def _process_pgp_key(self, rootkey, slot, key_features):
        """Process an unlocked PGP key and load it onto the OnlyKey."""
        keys = []
        is_ecc = False
        ecc_curve = 0

        algo_name = rootkey._key._pkalg._name_ if hasattr(rootkey._key._pkalg, '_name_') else str(rootkey._key._pkalg)

        if 'RSA' in algo_name:
            # RSA key - extract p and q
            primary_p = self._long_to_bytes(rootkey._key.keymaterial.p)
            primary_q = self._long_to_bytes(rootkey._key.keymaterial.q)
            keys.append({
                'name': 'Primary Key',
                'p': primary_p,
                'q': primary_q
            })
            # Process subkeys
            for subkey_id, subkey in rootkey._children.items():
                sub_algo = subkey._key._pkalg._name_ if hasattr(subkey._key._pkalg, '_name_') else str(subkey._key._pkalg)
                if 'RSA' in sub_algo:
                    sub_p = self._long_to_bytes(subkey._key.keymaterial.p)
                    sub_q = self._long_to_bytes(subkey._key.keymaterial.q)
                    keys.append({
                        'name': 'Subkey {}'.format(subkey_id),
                        'p': sub_p,
                        'q': sub_q
                    })
                elif hasattr(subkey._key.keymaterial, 's'):
                    is_ecc = True
                    sub_s = self._long_to_bytes(subkey._key.keymaterial.s)
                    keys.append({
                        'name': 'Subkey {}'.format(subkey_id),
                        's': sub_s
                    })
        elif 'EdDSA' in algo_name or 'ed25519' in algo_name.lower():
            is_ecc = True
            ecc_curve = 1  # Ed25519
            primary_s = self._long_to_bytes(rootkey._key.keymaterial.s)
            keys.append({
                'name': 'Primary Key',
                's': primary_s
            })
            for subkey_id, subkey in rootkey._children.items():
                sub_s = self._long_to_bytes(subkey._key.keymaterial.s)
                keys.append({
                    'name': 'Subkey {}'.format(subkey_id),
                    's': sub_s
                })
        elif 'ECDSA' in algo_name or 'ECDH' in algo_name:
            is_ecc = True
            # Determine curve from OID
            if hasattr(rootkey._key.keymaterial, 'oid'):
                oid = rootkey._key.keymaterial.oid
                oid_str = str(oid) if not isinstance(oid, str) else oid
                if 'nistp256' in oid_str or '1.2.840.10045.3.1.7' in oid_str:
                    ecc_curve = 2  # NIST P-256
                elif 'secp256k1' in oid_str or '1.3.132.0.10' in oid_str:
                    ecc_curve = 3  # secp256k1
                elif 'curve25519' in oid_str or '1.3.6.1.4.1.3029.1.5.1' in oid_str:
                    ecc_curve = 4  # Curve25519
                else:
                    ecc_curve = 1  # Default to Ed25519
            else:
                ecc_curve = 2  # Default to P-256 for ECDSA
            primary_s = self._long_to_bytes(rootkey._key.keymaterial.s)
            keys.append({
                'name': 'Primary Key',
                's': primary_s
            })
            for subkey_id, subkey in rootkey._children.items():
                sub_s = self._long_to_bytes(subkey._key.keymaterial.s)
                keys.append({
                    'name': 'Subkey {}'.format(subkey_id),
                    's': sub_s
                })
        else:
            raise RuntimeError('Unsupported key algorithm: {}'.format(algo_name))

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
                         payload=format(key_type, 'x') + hex_key)
        time.sleep(1)
        print(self.read_string())

    def loadprivate(self, rootkey_ascii_armor, rootkey_passphrase):
        """Legacy method - parse and display private keys from OpenPGP keys.

        For actually loading keys onto the device, use loadkey() instead.
        """
        try:
            import pgpy
        except ImportError:
            raise RuntimeError('pgpy is required. Install with: pip install pgpy')

        (rootkey, _) = pgpy.PGPKey.from_blob(rootkey_ascii_armor)

        assert rootkey.is_protected
        assert rootkey.is_unlocked is False

        try:
            with rootkey.unlock(rootkey_passphrase):
                # rootkey is now unlocked
                assert rootkey.is_unlocked
                print('rootkey is now unlocked')
                print('rootkey type %s', rootkey._key._pkalg)
                if 'RSA' in rootkey._key._pkalg._name_:
                    print('rootkey value:')
                    primary_keyp = self._long_to_bytes(rootkey._key.keymaterial.p)
                    primary_keyq = self._long_to_bytes(rootkey._key.keymaterial.q)
                    print(("".join(["%02x" % c for c in primary_keyp])) + ("".join(["%02x" % c for c in primary_keyq])))
                    print('rootkey size =', (len(primary_keyp)+len(primary_keyq))*8, 'bits')
                    print('subkey values:')
                    for subkey, value in rootkey._children.items():
                        print('subkey id', subkey)
                        sub_keyp = self._long_to_bytes(value._key.keymaterial.p)
                        sub_keyq = self._long_to_bytes(value._key.keymaterial.q)
                        print('subkey value')
                        print(("".join(["%02x" % c for c in sub_keyp])) + ("".join(["%02x" % c for c in sub_keyq])))
                        print('subkey size =', (len(primary_keyp)+len(primary_keyq))*8, 'bits')
                else:
                    print('rootkey value:')
                    primary_key = self._long_to_bytes(rootkey._key.keymaterial.s)
                    print("".join(["%02x" % c for c in primary_key]))
                    print('subkey values:')
                    for subkey, value in rootkey._children.items():
                        print('subkey id', subkey)
                        sub_key = self._long_to_bytes(value._key.keymaterial.s)
                        print('subkey value')
                        print("".join(["%02x" % c for c in sub_key]))

        except:
            print('Unlocking failed')

        # rootkey is no longer unlocked
        assert rootkey.is_unlocked is False

    def encrypt(self, slot):
        print('Unavailable command')

    def decrypt(self, slot):
        print('Unavailable command')

    def sign(self, slot):
        print('Unavailable command')

    def verify(self, slot):
        print('Unavailable command')