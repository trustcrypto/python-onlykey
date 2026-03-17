"""Tests for onlykey.pq — the canonical PQ helpers in python-onlykey.

Tests fingerprint computation, PQPublicInfo serialization, and
session key derivation. Does NOT require hardware — uses mock data.
"""
from __future__ import annotations

import hashlib
import os

import pytest

from onlykey.pq import (
    XWING_PK_SIZE,
    XWING_CT_SIZE,
    XWING_SS_SIZE,
    XWING_FINGERPRINT_LEN,
    xwing_fingerprint,
    derive_session_key,
    PQPublicInfo,
)


class TestXwingFingerprint:
    def test_correct_length(self):
        pk = os.urandom(XWING_PK_SIZE)
        fp = xwing_fingerprint(pk)
        assert len(fp) == XWING_FINGERPRINT_LEN

    def test_deterministic(self):
        pk = os.urandom(XWING_PK_SIZE)
        assert xwing_fingerprint(pk) == xwing_fingerprint(pk)

    def test_matches_sha256_prefix(self):
        pk = os.urandom(XWING_PK_SIZE)
        expected = hashlib.sha256(pk).digest()[:XWING_FINGERPRINT_LEN]
        assert xwing_fingerprint(pk) == expected

    def test_different_keys_different_fingerprints(self):
        pk1 = os.urandom(XWING_PK_SIZE)
        pk2 = os.urandom(XWING_PK_SIZE)
        assert xwing_fingerprint(pk1) != xwing_fingerprint(pk2)

    def test_wrong_size_raises(self):
        with pytest.raises(ValueError, match=str(XWING_PK_SIZE)):
            xwing_fingerprint(os.urandom(100))


class TestDeriveSessionKey:
    def test_correct_length(self):
        ss = os.urandom(XWING_SS_SIZE)
        key = derive_session_key(ss)
        assert len(key) == 32

    def test_custom_length(self):
        ss = os.urandom(XWING_SS_SIZE)
        key = derive_session_key(ss, key_len=64)
        assert len(key) == 64

    def test_deterministic(self):
        ss = os.urandom(XWING_SS_SIZE)
        k1 = derive_session_key(ss, context=b"test")
        k2 = derive_session_key(ss, context=b"test")
        assert k1 == k2

    def test_different_contexts(self):
        ss = os.urandom(XWING_SS_SIZE)
        k1 = derive_session_key(ss, context=b"context-a")
        k2 = derive_session_key(ss, context=b"context-b")
        assert k1 != k2

    def test_different_secrets(self):
        ss1 = os.urandom(XWING_SS_SIZE)
        ss2 = os.urandom(XWING_SS_SIZE)
        k1 = derive_session_key(ss1, context=b"test")
        k2 = derive_session_key(ss2, context=b"test")
        assert k1 != k2

    def test_wrong_ss_size_raises(self):
        with pytest.raises(ValueError, match=str(XWING_SS_SIZE)):
            derive_session_key(os.urandom(16))


class TestPQPublicInfo:
    def test_from_raw(self):
        pk = os.urandom(XWING_PK_SIZE)
        info = PQPublicInfo.from_raw(pk)
        assert info.public_key == pk
        assert len(info.fingerprint) == XWING_FINGERPRINT_LEN

    def test_verify_fingerprint(self):
        pk = os.urandom(XWING_PK_SIZE)
        info = PQPublicInfo.from_raw(pk)
        assert info.verify_fingerprint() is True

    def test_tampered_fingerprint(self):
        pk = os.urandom(XWING_PK_SIZE)
        bad = PQPublicInfo(public_key=pk, fingerprint=b"\xff" * XWING_FINGERPRINT_LEN)
        assert bad.verify_fingerprint() is False

    def test_wrong_pk_size(self):
        with pytest.raises(ValueError):
            PQPublicInfo(public_key=b"\x00" * 100, fingerprint=b"\x00" * XWING_FINGERPRINT_LEN)

    def test_wrong_fp_size(self):
        with pytest.raises(ValueError):
            PQPublicInfo(public_key=os.urandom(XWING_PK_SIZE), fingerprint=b"\x00" * 4)

    def test_round_trip_dict(self):
        pk = os.urandom(XWING_PK_SIZE)
        info = PQPublicInfo.from_raw(pk)
        d = info.to_dict()
        info2 = PQPublicInfo.from_dict(d)
        assert info.public_key == info2.public_key
        assert info.fingerprint == info2.fingerprint

    def test_dict_fields(self):
        pk = os.urandom(XWING_PK_SIZE)
        info = PQPublicInfo.from_raw(pk)
        d = info.to_dict()
        assert d["algorithm"] == "X-Wing"
        assert d["kem"] == "mlkem768x25519"
        assert d["pk_size"] == str(XWING_PK_SIZE)
        assert "public_key_hex" in d
        assert "fingerprint_hex" in d
