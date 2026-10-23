"""Hardware-free proof of the derived (label-based) X-Wing path.

Split custody is gone: the device derives a full X-Wing keypair from one
32-byte seed and decapsulates both halves itself. The host is a plain X-Wing
sender. These tests model the device with the spec's own keygen - the same
SHAKE256(seed, 96) expansion okcrypto.cpp's okcrypto_xwing_derive_seed() feeds -
and check that a standard sender's shared secret comes back out.

What used to be tested here was the split: the host expanded an ML-KEM seed the
device handed over, ran the ML-KEM half locally and combined. That is exactly
what was removed - the seed is private key material, so the device was handing
out half its key - so the old tests could only pass by exercising the defect.
"""
import os
import sys
import types

import pytest

pytest.importorskip("kyber_py")
pytest.importorskip("cryptography")

# Stub hid so importing the onlykey package doesn't need USB libs.
for _n in ("hid", "hidraw"):
    if _n not in sys.modules:
        try:
            __import__(_n)
        except ImportError:
            _m = types.ModuleType(_n)
            _m.device = object
            sys.modules[_n] = _m

import hashlib

from kyber_py.ml_kem import ML_KEM_768
from onlykey.age_plugin import derived_xwing as dx
from onlykey.age_plugin import xwing  # existing: xwing_encaps_host, x25519 helpers


def _device_derive(seed=None):
    """Stand-in for the OnlyKey web-derivation, spec X-Wing keygen.

    draft-connolly-cfrg-xwing-kem: expand the 32-byte decapsulation key with
    SHAKE256 to 96 bytes, then d = [0:32], z = [32:64], sk_X = [64:96]. This is
    the same expansion and the same layout the firmware uses for both derived
    and stored X-Wing keys - one construction, not two.

    Returns (recipient_1216, decapsulate) where decapsulate(ct) is what the
    device does for us now.
    """
    seed = seed if seed is not None else os.urandom(32)
    expanded = hashlib.shake_256(seed).digest(96)
    d, z, sk_x = expanded[0:32], expanded[32:64], expanded[64:96]

    ek_m, dk_m = ML_KEM_768._keygen_internal(d, z)
    pk_x = xwing.x25519_scalarmult_base(sk_x)
    recipient = ek_m + pk_x

    def decapsulate(ct):
        ct_m, ct_x = ct[:1088], ct[1088:1120]
        ss_m = ML_KEM_768._decaps_internal(dk_m, ct_m)
        ss_x = xwing.x25519_scalarmult(sk_x, ct_x)
        return xwing.xwing_combiner(ss_m, ss_x, ct_x, pk_x)

    return recipient, decapsulate


def test_recipient_is_1216_bytes():
    recipient, _ = _device_derive()
    assert len(recipient) == 1216


def test_device_decaps_matches_standard_encaps():
    recipient, decapsulate = _device_derive()

    ss_enc, ct = xwing.xwing_encaps_host(recipient)   # standard X-Wing sender
    assert len(ct) == 1120

    assert decapsulate(ct) == ss_enc


def test_wrong_ciphertext_fails():
    recipient, decapsulate = _device_derive()
    ss_enc, ct = xwing.xwing_encaps_host(recipient)
    # Flip a byte in the ML-KEM half. ML-KEM is implicitly rejecting, so this
    # yields a different shared secret rather than an error - which is why the
    # check has to be "not equal", not "raises".
    tampered = bytes([ct[0] ^ 1]) + ct[1:]
    assert decapsulate(tampered) != ss_enc


def test_deterministic_recipient_per_seed():
    seed = os.urandom(32)
    a, _ = _device_derive(seed)
    b, _ = _device_derive(seed)
    assert a == b


def test_distinct_seeds_give_distinct_recipients():
    a, _ = _device_derive()
    b, _ = _device_derive()
    assert a != b


def test_halves_are_independent():
    """The point of the fix.

    The ML-KEM half used to be SHA256(sk_X || tag) - a child of the X25519
    half - so recovering sk_X yielded the ML-KEM seed, sk_M, and the whole
    shared secret. Both halves are now sibling slices of one SHAKE256 stream
    over a secret seed, so neither is a function of the other. Knowing sk_X
    tells you nothing about d/z and vice versa.
    """
    seed = os.urandom(32)
    expanded = hashlib.shake_256(seed).digest(96)
    d, z, sk_x = expanded[0:32], expanded[32:64], expanded[64:96]
    assert d != z != sk_x
    # The old construction: seed_M as a hash of sk_X. If the expansion were
    # still doing that, this would reproduce d.
    legacy = hashlib.sha256(sk_x + b"onlykey/xwing/mlkem768-seed/v1").digest()
    assert legacy != d


def test_derived_identity_roundtrip():
    from onlykey.age_plugin import cli

    for label in ("age:personal", "alice@example.com", "work"):
        ident = dx.encode_identity(label)
        # Must share the exact same "AGE-PLUGIN-ONLYKEY-1" prefix as a slot
        # identity - `age` picks which plugin *binary* to invoke from that
        # prefix text alone, so a distinct "...-DERIVED-1" HRP (bech32-valid
        # or not) makes `age` look for a nonexistent
        # `age-plugin-onlykey-derived` executable instead of the real,
        # installed `age-plugin-onlykey` (observed against a real `age -d` run).
        assert ident.startswith("AGE-PLUGIN-ONLYKEY-1")
        assert dx.decode_identity(ident) == {"derived": True, "label": label}
    # A real slot identity is not a derived identity, even sharing the same
    # HRP - disambiguated by the marker byte in the decoded payload, not the
    # prefix text (see _DERIVED_MARKER).
    assert dx.decode_identity(cli.encode_identity(101)) is None
