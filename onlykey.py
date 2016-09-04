# coding: utf-8
import hid
from aenum import Enum

ID_VENDOR = 5824
ID_PRODUCT = 1158

MAX_INPUT_REPORT_SIZE = 64
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
    OKGETSSHPKEY = 236  # XXX(tsileo): my own testing


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


class OnlyKey(object):
    def __init__(self):
        self._hid = hid.device()
        self._hid.open(ID_VENDOR, ID_PRODUCT)

    def initialized(self):
        assert self._read_string() == 'INITIALIZED'

    def send_message(self, payload='', msg=None, slot_id=None, message_field=None):
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

        # Append the raw payload, expect a string from now
        if payload:
            for c in payload:
                raw_bytes.append(ord(c))
        while len(raw_bytes) < MAX_INPUT_REPORT_SIZE:
            raw_bytes.append(0)

        # Send the message
        self._hid.write(raw_bytes)

    def read_string(self):
        """Read an ASCII string."""
        return ''.join([chr(item) for item in self._hid.read(MAX_INPUT_REPORT_SIZE) if item != 0])
