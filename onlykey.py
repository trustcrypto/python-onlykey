# coding: utf-8
import hid
ID_VENDOR = 5824
ID_PRODUCT = 1158

MESSAGES = {
    'OKSETPIN': 225,  # 0xE1
    'OKSETSDPIN': 226,  # 0xE2
    'OKSETPDPIN': 227,  # 0xE3
    'OKSETTIME': 228,  # 0xE4
    'OKGETLABELS': 229,  # 0xE5
    'OKSETSLOT': 230,  # 0xE6
    'OKWIPESLOT': 231,  # 0xE7
    'OKSETU2FPRIV': 232,  # 0xE8
    'OKWIPEU2FPRIV': 233,  # 0xE9
    'OKSETU2FCERT': 234,  # 0xEA
    'OKWIPEU2FCERT': 235,  # 0xEB
}
MAX_INPUT_REPORT_SIZE = 64
MATX_OUTPUT_REPORT_SIZE = 64
MAX_FEATURE_REPORTS = 0
MESSAGE_HEADER = [255, 255, 255, 255]

MESSAGE_FIELDS = {
    'LABEL': 1,
    'USERNAME': 2,
    'NEXTKEY1': 3,
    'DELAY1': 4,
    'PASSWORD': 5,
    'NEXTKEY2': 6,
    'DELAY2': 7,
    'TFATYPE': 8,
    'TFAUSERNAME': 9,
    'YUBIAUTH': 10
}


class OnlyKey(object):
    def __init__(self):
        self._hid = hid.device()
        self._hid.open(ID_VENDOR, ID_PRODUCT)
        self._connection = -1
        self._is_receive_pending = False
        self._poll_enabled = False
        self._is_initialized = False
        self._is_locked = False
        self._last_messages = {
            'sent': [],
            'received': [],
        }
        self._current_slot_id = None
        self._labels = []
