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
    OKGETSSHPUBKEY = 236  # XXX(tsileo): my own testing
    OKSIGNSSHCHALLENGE = 237
    OKWIPESSHPRIV = 238
    OKSETSSHPRIV = 239


class MessageField(Enum):
    LABEL = 1
    USERNAME = 2
    NEXTKEY1 = 3
    DELAY1 = 4
    PASSWORD = 5
    NEXTKEY2 = 6
    DELAY2 = 7
    TFATYPE = 8
    TFAUSERNAME = 9
    YUBIAUTH = 10


class OnlyKeyUnavailableException(Exception):
    """Exception raised when the connection to the OnlyKey failed."""
    pass


class Slot(object):
    def __init__(self, num, label=''):
        self.number = num
        self.label = label

    def __repr__(self):
        return '<Slot \'{}|{}\'>'.format(self.number, self.label)


class OnlyKey(object):
    def __init__(self, connect=True):
        self._hid = hid.device()
        if connect:
            tries = 3
            while tries > 0:
                try:
                    self._connect()
                    return
                except Exception, e:
                    log.debug('connect failed, trying again in 1 second...')
                    time.sleep(1)
                    tries -= 1

            raise e

    def _connect(self):
        try:
            self._hid.open(ID_VENDOR, ID_PRODUCT)
        except:
            log.exception('failed to connect')
            raise OnlyKeyUnavailableException()

    def initialized(self):
        return self._read_string() == 'INITIALIZED'

    def send_message(self, payload=None, msg=None, slot_id=None, message_field=None):
        """Send a message."""
        # Initialize an empty message with the header
        raw_bytes = list(MESSAGE_HEADER)

        # Append the message type (must be `Message` enum value)
        if msg:
            raw_bytes.append(msg.value)

        # Append the slot ID if needed
        if slot_id:
            raw_bytes.append(slot_id)

        # Append the message field (must be a `MessageField` enum value)
        if message_field:
            raw_bytes.append(message_field.value)

        # Append the raw payload, expect a string or a list of int
        if payload:
            if isinstance(payload, str):
                for c in payload:
                    raw_bytes.append(ord(c))
            else:
                raw_bytes.extend(payload)

        # Pad the ouput with 0s
        while len(raw_bytes) < MAX_INPUT_REPORT_SIZE:
            raw_bytes.append(0)

        # Send the message
        self._hid.write(raw_bytes)

    def send_large_message(self, payload=None, msg=None):
        """Wrapper for sending large message (larger than 58 bytes) in batch in a transparent way."""
        if not msg:
            raise Exception("Missing msg")

        # Split the payload in multiple chunks
        chunks = [payload[x:x+MAX_LARGE_PAYLOAD_SIZE] for x in xrange(0, len(payload), 58)]
        for chunk in chunks:
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

    def read_bytes(self, n=64, to_str=False, timeout_ms=5000):
        """Read n bytes and return an array of uint8 (int)."""
        out = self._hid.read(n, timeout_ms=timeout_ms)
        if to_str:
            # Returns the bytes a string if requested
            return ''.join([chr(c) for c in out])

        # Returns the raw list
        return out

    def read_string(self, timeout_ms=5000):
        """Read an ASCII string."""
        return ''.join([chr(item) for item in self._hid.read(MAX_INPUT_REPORT_SIZE, timeout_ms) if item != 0])

    def getlabels(self):
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
        if slot_number >= 10:
            slot_number += 6
        self.send_message(msg=Message.OKSETSLOT, slot_id=slot_number, message_field=message_field, payload=value)
        print self.read_string()
        # Set U2F
        # [255, 255, 255, 255, 230, 12, 8, 117, 50, 102, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

    def wipeslot(self, slot_number):
        # Seems to be 8 message to read
        pass
