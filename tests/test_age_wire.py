"""Hardware-free checks of the PQ HID wire framing (onlykey_hid).

Verifies that ML-KEM / X-Wing requests target a real ECC slot (101-116) and
carry the firmware key-type byte in buffer[6], matching the firmware dispatch
in okcrypto.cpp (slot in buffer[5], key type in buffer[6], payload in buffer[7:]).
No OnlyKey hardware is used — a fake transport records what would be sent.
"""
import sys
import types

import pytest

# Stub hid so importing the onlykey package doesn't need USB libraries.
for _name in ("hid", "hidraw"):
    if _name not in sys.modules:
        try:
            __import__(_name)
        except ImportError:
            _m = types.ModuleType(_name)
            _m.device = object
            sys.modules[_name] = _m

import pytest as _pytest

from onlykey.client import Message, OnlyKey
from onlykey.age_plugin import (
    DEFAULT_MLKEM_SLOT, DEFAULT_XWING_SLOT,
    KEYTYPE_MLKEM768, KEYTYPE_XWING, validate_ecc_slot,
)
from onlykey.age_plugin.onlykey_hid import OnlyKeyPQ


class FakeOK:
    """Records send_message calls; feeds zero bytes back for reads.

    Reuses the real OnlyKey.send_large_message2 so the multi-packet decaps
    framing is exercised for real (it only calls self.send_message).
    """

    send_large_message2 = OnlyKey.send_large_message2

    def __init__(self):
        self.sent = []

    def send_message(self, msg=None, slot_id=None, payload=None, **kw):
        self.sent.append({
            "msg": msg,
            "slot": slot_id,
            "body": bytes(payload) if payload is not None else b"",
        })

    def read_bytes(self, n, timeout_ms=0):
        return bytes(n)  # 64 zero bytes per read

    def read_string(self, timeout_ms=0):
        return ""


def _dev():
    # Passing ok= skips the hardware _connect().
    return OnlyKeyPQ(ok=FakeOK())


def test_slot_validation_user_slots_only():
    # User ECC key slots 101-116 are valid; 117-132 are reserved and rejected.
    for s in range(101, 117):
        assert validate_ecc_slot(s) == s
    for bad in (100, 117, 128, 132, 133, 1, 200):   # 117-132 reserved
        with _pytest.raises(ValueError):
            validate_ecc_slot(bad)
    assert KEYTYPE_MLKEM768 == 5
    assert KEYTYPE_XWING == 6


@_pytest.mark.parametrize("slot", [101, 108, 116])
def test_xwing_framing_any_slot(slot):
    dev = _dev()
    dev.xwing_getpubkey(slot)
    f = dev.ok.sent[-1]
    assert f["msg"] == Message.OKGETPUBKEY
    assert f["slot"] == slot
    assert f["body"][0] == KEYTYPE_XWING            # buffer[6]

    dev.xwing_keygen(slot)
    f = dev.ok.sent[-1]
    assert f["msg"] == Message.OKSETPRIV            # keygen via OKSETPRIV
    assert f["slot"] == slot
    assert f["body"][0] == KEYTYPE_XWING
    assert f["body"][1:9] == b"\xff" * 8           # generate-on-device trigger


@_pytest.mark.parametrize("slot", [101, 110, 116])
def test_decaps_is_multipacket_and_reassembles(slot):
    """Decaps streams the 1120-byte ciphertext via send_large_message2.

    Each packet is [slot, 0xFF(more) or final-length, <=57 bytes]; the firmware
    accumulates them. No key-type byte is sent — the device reads it from the
    stored key. Reassembling the packet bodies must reproduce the ciphertext.
    """
    dev = _dev()
    ct = bytes((i % 251) for i in range(1120))     # distinct, non-trivial bytes
    dev.xwing_decaps(ct, slot=slot)

    pkts = dev.ok.sent
    assert len(pkts) > 1                            # genuinely multi-packet
    assert all(p["msg"] == Message.OKDECRYPT for p in pkts)
    assert all(p["body"][0] == slot for p in pkts)  # buffer[5] = slot in every packet
    flags = [p["body"][1] for p in pkts]
    assert all(f == 0xFF for f in flags[:-1])       # 0xFF = "more coming"
    assert flags[-1] == len(pkts[-1]["body"]) - 2   # final packet carries its length
    # reassemble payload (skip the 2-byte [slot, flag] header on each packet)
    reassembled = b"".join(bytes(p["body"][2:]) for p in pkts)
    assert reassembled == ct
    assert len(reassembled) == 1120


def test_defaults_and_mlkem_framing():
    dev = _dev()
    dev.xwing_getpubkey()
    assert dev.ok.sent[-1]["slot"] == DEFAULT_XWING_SLOT

    dev.mlkem_keygen(110)
    f = dev.ok.sent[-1]
    assert f["msg"] == Message.OKSETPRIV
    assert f["slot"] == 110
    assert f["body"][0] == KEYTYPE_MLKEM768
    assert f["body"][1:9] == b"\xff" * 8

    dev.mlkem_getpubkey()
    assert dev.ok.sent[-1]["slot"] == DEFAULT_MLKEM_SLOT


def test_reserved_slot_rejected():
    dev = _dev()
    for reserved in (117, 128, 132):
        with _pytest.raises(ValueError):
            dev.xwing_getpubkey(reserved)
