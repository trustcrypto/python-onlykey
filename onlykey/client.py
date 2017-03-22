# coding: utf-8
import logging
import time

import hid
from aenum import Enum

log = logging.getLogger(__name__)

ID_VENDOR = 5824
ID_PRODUCT = 1158

MAX_INPUT_REPORT_SIZE = 64
MAX_LARGE_PAYLOAD_SIZE = 58  # 64 - <4 bytes header> - <1 byte message> - <1 byte size|0xFF if max>
MATX_OUTPUT_REPORT_SIZE = 64
MAX_FEATURE_REPORTS = 0
MESSAGE_HEADER = [255, 255, 255, 255]

SLOTS_NAME= {
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
    OKSIGNCHALLENGE = 237
    OKWIPEPRIV = 238
    OKSETPRIV = 239
    OKDECRYPT = 240
    OKRESTORE = 241


class MessageField(Enum):
    LABEL = 1
    URL = 15
    NEXTKEY1 = 16
    DELAY1 = 17
    USERNAME = 2
    NEXTKEY2 = 3
    DELAY2 = 4
    PASSWORD = 5
    NEXTKEY3 = 6
    DELAY3 = 7
    TFATYPE = 8
    TOTPKEY = 9
    YUBIAUTH = 10
    IDLETIMEOUT = 11
    WIPEMODE = 12
    KEYTYPESPEED = 13
    KEYLAYOUT = 14

class KeyTypeEnum(Enum):
    ED22519 = 1
    P256 = 2
    SECP256K1 = 3

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

class OnlyKey(object):
    def __init__(self, connect=True):
        self._hid = hid.device()
        if connect:
            tries = 5
            while tries > 0:
                try:
                    self._connect()
                    logging.debug('connected')
                    return
                except Exception, e:
                    log.debug('connect failed, trying again in 1 second...')
                    time.sleep(1.5)
                    tries -= 1

            raise e

    def _connect(self):
        try:
            self._hid.open(ID_VENDOR, ID_PRODUCT)
            #self._hid.set_nonblocking(1)
        except:
            log.exception('failed to connect')
            raise OnlyKeyUnavailableException()

    def close(self):
        return self._hid.close()

    def initialized(self):
        return self._read_string() == 'INITIALIZED'

    def set_ecc_key(self, key_type, slot, key):
        payload = [key_type, slot] + [ord(c) for c in key]
        self.send_message(msg=Message.OKSETPRIV, payload=payload)

    def set_rsa_key(self, key_type, slot, key):
        payload = [key_type, slot] + [ord(c) for c in key]
        self.send_message(msg=Message.OKSETPRIV, payload=payload)

    def send_message(self, payload=None, msg=None, slot_id=None, message_field=None):
        """Send a message."""
        logging.debug('preparing payload for writing')
        # Initialize an empty message with the header
        raw_bytes = list(MESSAGE_HEADER)

        # Append the message type (must be `Message` enum value)
        if msg:
            logging.debug('msg=%s', msg.name)
            raw_bytes.append(msg.value)

        # Append the slot ID if needed
        if slot_id:
            logging.debug('slot_id=%s', slot_id)
            raw_bytes.append(slot_id)

        # Append the message field (must be a `MessageField` enum value)
        if message_field:
            logging.debug('slot_field=%s', message_field.name)
            raw_bytes.append(message_field.value)

        # Append the raw payload, expect a string or a list of int
        if payload:
            if isinstance(payload, (str, unicode)):
                logging.debug('payload="%s"', payload)
                for c in payload:
                    raw_bytes.append(ord(c))
            elif isinstance(payload, list):
                logging.debug('payload=%s', ''.join([chr(c) for c in payload]))
                raw_bytes.extend(payload)
            else:
                raise Exception('`payload` must be either `str` or `list`')

        # Pad the ouput with 0s
        while len(raw_bytes) < MAX_INPUT_REPORT_SIZE:
            raw_bytes.append(0)

        # Send the message
        logging.debug('sending message')
        print 'send_message', len(raw_bytes)
        print raw_bytes
        self._hid.write(raw_bytes)

    def send_large_message(self, payload=None, msg=None, slot_id=chr(101)):
        """Wrapper for sending large message (larger than 58 bytes) in batch in a transparent way."""
        if not msg:
            raise Exception("Missing msg")

        # Split the payload in multiple chunks
        chunks = [payload[x:x+MAX_LARGE_PAYLOAD_SIZE] for x in xrange(0, len(payload), 58)]
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
        chunks = [payload[x:x+MAX_LARGE_PAYLOAD_SIZE-1] for x in xrange(0, len(payload), 57)]
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
                    current_payload.append(ord(c))

            self.send_message(payload=current_payload, msg=msg)

        return



    def send_large_message3(self, payload=None, msg=None, slot_id=101, key_type=1):
        """Wrapper for sending large message (larger than 58 bytes) in batch in a transparent way."""
        if not msg:
            raise Exception("Missing msg")

        # Split the payload in multiple chunks
        chunks = [payload[x:x+MAX_LARGE_PAYLOAD_SIZE-1] for x in xrange(0, len(payload), 57)]
        for chunk in chunks:
            # print chunk
            # print [ord(c) for c in chunk]
            current_payload = [slot_id, key_type]

            # Append the actual payload
            if isinstance(chunk, list):
                current_payload.extend(chunk)
            else:
                for c in chunk:
                    current_payload.append(ord(c))

            self.send_message(payload=current_payload, msg=msg)

        return

    def read_bytes(self, n=64, to_str=False, timeout_ms=100):
        """Read n bytes and return an array of uint8 (int)."""
        out = self._hid.read(n, timeout_ms=timeout_ms)
        logging.debug('read="%s"', ''.join([chr(c) for c in out]))
        if to_str:
            # Returns the bytes a string if requested
            return ''.join([chr(c) for c in out])

        # Returns the raw list
        return out

    def read_string(self, timeout_ms=2000):
        """Read an ASCII string."""
        return ''.join([chr(item) for item in self.read_bytes(MAX_INPUT_REPORT_SIZE, timeout_ms=timeout_ms) if item != 0])

    def getlabels(self):
        """Fetch the list of `Slot` from the OnlyKey.

        No need to read messages.
        """
        self.send_message(msg=Message.OKGETLABELS)
        time.sleep(0.2)
        slots = []
        for _ in range(12):
            data = self.read_string().split('|')
            slot_number = ord(data[0])
            if slot_number >= 16:
                slot_number = slot_number - 6
            if 1 <= slot_number <= 12:
                slots.append(Slot(slot_number, label=data[1]))
        return slots

    def setslot(self, slot_number, message_field, value):
        """Set a slot field to the given value.
        """
        if slot_number >= 10:
            slot_number += 6
        self.send_message(msg=Message.OKSETSLOT, slot_id=slot_number, message_field=message_field, payload=value)
        # Set U2F
        # [255, 255, 255, 255, 230, 12, 8, 117, 50, 102, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        print self.read_string()

    def wipeslot(self, slot_number):
        """Wipe all the fields for the given slot."""
        self.send_message(msg=Message.OKWIPESLOT, slot_id=slot_number)
        for _ in xrange(8):
            print self.read_string()
