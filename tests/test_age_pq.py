"""Hardware-free tests for the post-quantum age plugin (ML-KEM-768 / X-Wing).

These exercise the host-side cryptography only — ML-KEM-768 encapsulation,
the X-Wing hybrid combiner, and the HPKE seal/open that backs age's
``mlkem768x25519`` stanza. Decapsulation that would normally run on the
OnlyKey is emulated in software via ``mlkem_py`` so the full KEM roundtrip
can be verified without a device.

Run with:  pytest tests/test_age_pq.py
Requires:  cryptography, kyber-py  (installed via the ``age`` extra)
"""
import os
import sys
import types

import pytest

# Skip the whole module if the PQ crypto deps aren't present (e.g. the
# package was installed without the ``age`` extra).
pytest.importorskip("cryptography")
pytest.importorskip("kyber_py")

# Importing the onlykey package pulls in onlykey.client, which imports hid.
# In CI without USB libraries, provide a stub so the import succeeds — the
# tests below never touch a real device.
for _name in ("hid", "hidraw"):
    if _name not in sys.modules:
        try:
            __import__(_name)
        except ImportError:
            _stub = types.ModuleType(_name)
            _stub.device = object
            sys.modules[_name] = _stub

from onlykey.age_plugin import protocol, xwing
from onlykey.age_plugin.mlkem_py import (
    mlkem768_decaps,
    mlkem768_encaps,
    mlkem768_keygen,
)


def test_mlkem768_sizes_and_roundtrip():
    ek, dk = mlkem768_keygen()
    assert len(ek) == 1184
    assert len(dk) == 2400
    ss, ct = mlkem768_encaps(ek)
    assert len(ss) == 32
    assert len(ct) == 1088
    assert mlkem768_decaps(dk, ct) == ss


def _xwing_keypair():
    """Build an X-Wing keypair: (ek_M, dk_M, sk_X, pk_X, pk_xwing)."""
    ek, dk = mlkem768_keygen()
    sk_x, pk_x = xwing.x25519_keygen()
    pk = ek + pk_x  # pk_M(1184) || pk_X(32)
    return ek, dk, sk_x, pk_x, pk


def test_xwing_encaps_decaps_agree():
    _, dk, sk_x, pk_x, pk = _xwing_keypair()
    assert len(pk) == 1216

    ss, ct = xwing.xwing_encaps_host(pk)
    assert len(ss) == 32
    assert len(ct) == 1120

    ct_m, ct_x = ct[:1088], ct[1088:1120]
    ss_m = mlkem768_decaps(dk, ct_m)
    ss_x = xwing.x25519_scalarmult(sk_x, ct_x)
    ss_dec = xwing.xwing_combiner(ss_m, ss_x, ct_x, pk_x)

    assert ss_dec == ss


def test_hpke_seal_open_file_key():
    _, dk, sk_x, pk_x, pk = _xwing_keypair()
    ss, ct = xwing.xwing_encaps_host(pk)

    ct_m, ct_x = ct[:1088], ct[1088:1120]
    ss_dec = xwing.xwing_combiner(
        mlkem768_decaps(dk, ct_m), xwing.x25519_scalarmult(sk_x, ct_x), ct_x, pk_x
    )

    file_key = os.urandom(16)
    aead_ct = xwing.seal_file_key(ss, ct, file_key)
    assert len(aead_ct) == 32
    assert xwing.open_file_key(ss_dec, ct, aead_ct) == file_key


def test_wrong_identity_is_rejected():
    _, dk, sk_x, pk_x, pk = _xwing_keypair()
    ss, ct = xwing.xwing_encaps_host(pk)
    ct_m, ct_x = ct[:1088], ct[1088:1120]
    aead_ct = xwing.seal_file_key(ss, ct, os.urandom(16))

    _, dk_bad = mlkem768_keygen()
    ss_bad = xwing.xwing_combiner(
        mlkem768_decaps(dk_bad, ct_m), xwing.x25519_scalarmult(sk_x, ct_x), ct_x, pk_x
    )
    with pytest.raises(Exception):
        xwing.open_file_key(ss_bad, ct, aead_ct)


def test_xwing_spec_constants():
    # draft-connolly-cfrg-xwing-kem-09
    assert xwing.KEM_ID == 0x647A
    assert xwing.KDF_ID == 0x0001
    assert xwing.AEAD_ID == 0x0003
    assert xwing.XWING_LABEL.hex() == "5c2e2f2f5e5c"


def test_age_stanza_roundtrip():
    blob = os.urandom(1120)
    assert protocol.b64decode_no_pad(protocol.b64encode_no_pad(blob)) == blob
    st = protocol.Stanza("mlkem768x25519", [protocol.b64encode_no_pad(blob)], os.urandom(32))
    assert "mlkem768x25519" in st.encode()
