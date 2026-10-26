"""Known-answer test against the C2SP age specification.

The identity, encapsulated key and stanza body are the mlkem768x25519 example
from age.md (github.com/C2SP/C2SP). A file key recovered from them proves the
plugin writes and reads the same construction as the age tool: X-Wing shared
secret straight into the HPKE key schedule, info "age-encryption.org/mlkem768x25519".
"""
import base64
import hashlib

import pytest

from onlykey.age_plugin import xwing
from onlykey.age_plugin.bech32 import bech32_decode

kyber = pytest.importorskip("kyber_py.ml_kem")

IDENTITY = "AGE-SECRET-KEY-PQ-1XX76JRALNLXDMEW0CRK45QMCCH4X06SE84UN3VPM33W6HWDX0H3SK3ZQFR"
ENC_B64 = "".join([
    'U7E10Aon27j1oDrH7fP3B++SPROSnDVvQpBemzOM+ZcsojxJifUbeeYWejMYKNB+H3rlXNvgtDKf',
    'SCkt78oqncr3faY1JtMj0GQPBZ2g6t8o1cMzZgyLMepeVuTQKxLqnM6L48n8dJL2y0N3i7WSOV6c',
    'sB79r9tcIs88Al9iCwVLpt74OzDXAIwD1QlCAvj75ZEnwtgP6Xr6s+wHg9hLD0OSSQOaTdCqzR5s',
    'hQWyrjVs7GCqd/5WbNGYNaolPQJBu9wTNhHjP9XGCTv8iKXkYwXDYujInkF5hOjpCHE8Vu+9UeMI',
    '+l0GJAEervT51bwaf288GiqgapP5g4HF8V4P0+03B/SwXhvxxZpKjTU2OcFS8I9chtEZ7Ucw5bvP',
    'kC1lyjNnqQXZyc4JnAqbFQTlPGnwbEsm0UGE+v0FOxTBznIivHoPHV++5PuYpombiV/lfYy8BFx0',
    'Hk1igNI3iLNjlIg4MLXNWjN3VROlXIiSsWNXjr/Frh/OE87PXoaKhsDPWfv6akd9PxSDqJMQ4j8k',
    '11kCSOnnU8Rw4TSVnTpt7gfYzBULrMr7qDgyH/TYvp0o7mAq4IaraFJmTqm+LjfAJT4PCQOpnMNR',
    'HLyXZn6mtMUujNv7+zR/I9Vqi+bJdQBwNWdJcUQVarqx2zxV2rM7l+j0gsmxjxp5yAPyALzla7Xz',
    'VvbboLMnHeM+CzN4GoB2PC4neVDSw7Dfs8vbm7f9CeDGvhjWrzcSCOsUCalvH1WkbpE0b9cE/TSJ',
    'qwXFXEc8npTSQWH58RXDALNF3qCbW5LaboD4wCloClEakgljT0s0mTdqIwzj4xtdlX0S2dCtaV5M',
    'HQJiQHGwPvBSCiIsh8ZWJPwZ7Ron7xoWgNI0lXRqhKm7fvFNCzF+Ray2kOyKWHbsMy3a5Zx3yZxC',
    'GFwexAxgYfAH9HJ1raHi1XYGpNpBlDXg47U1y4uU7RBeBb4ewETv/B/p8sGW88tIY87dHM2xHjnn',
    'tGXLvkCIkmjXGNULAVYHxDPJTygxSF7uTVPYCBUk5KeLnDVcgWF8p/wxigza47ptMtpVtm9ZrSEu',
    '9vzOnaTN3KO75RkkLuZszhXfmMZ46NQrdS7Y6duCiN501BnR5BUC4dX4iMxchix6aLN3pKv6UOEw',
    'wcx2aSF4Ib963MAtTPEjhqe+dt0VcTar/08uLWv1kQQueFaEGet4KQ975ZqaoU3PmZH9gqTOumX1',
    'EKf0Pnl0F3NMW+lEOlnCEce99zHBwBf7LV0pLNLDONBxpQySrZUQsNfhAq2Ktf5nG2hcGAMFMWIs',
    'EOuOyzEe+l2aHW4/ojOjU1Oqy4TLzVVRlWmPxQde7qKbvBN7CQhDqJHJA2nphQT/4DOdLqkwRiau',
    'Mmnfx9FI3+hYnX25NpnyvM/Pt94vpsRkhcuttu4/G4xOYTNQd2YWjGwhypZ0oPSiriuTbhj6y2qm',
    '33jiwxvegeDz8CmAIhOEY2JoVpjjX9XzuNR2f5KTLmLzEkOcJQ',
])
BODY_B64 = "c/k+TjhBA6Je1DF8rxZhe2Jm8CN0zbkV9rre6nA8g98"
# Recovered by OpenBase with the spec parameters (and by nothing else).
FILE_KEY = bytes.fromhex("df56f61c8e496609c18d25c197451803")


def _b64(s):
    return base64.b64decode(s + "=" * (-len(s) % 4))


def _identity_decaps(seed, enc):
    """What the device does for a stored X-Wing key: SHAKE256 expansion to
    d || z || sk_X, ML-KEM decaps, X25519, combiner."""
    expanded = hashlib.shake_256(seed).digest(96)
    d, z, sk_x = expanded[0:32], expanded[32:64], expanded[64:96]
    _, dk_m = kyber.ML_KEM_768._keygen_internal(d, z)
    pk_x = xwing.x25519_scalarmult_base(sk_x)
    ct_m, ct_x = enc[:1088], enc[1088:1120]
    ss_m = kyber.ML_KEM_768._decaps_internal(dk_m, ct_m)
    ss_x = xwing.x25519_scalarmult(sk_x, ct_x)
    return xwing.xwing_combiner(ss_m, ss_x, ct_x, pk_x)


def _vector():
    hrp, seed = bech32_decode(IDENTITY)
    assert hrp == "age-secret-key-pq-"
    enc, body = _b64(ENC_B64), _b64(BODY_B64)
    assert len(seed) == 32 and len(enc) == 1120 and len(body) == 32
    return bytes(seed), enc, body


def test_opens_the_spec_example():
    seed, enc, body = _vector()
    ss = _identity_decaps(seed, enc)
    assert xwing.open_file_key(ss, enc, body) == FILE_KEY


def test_seal_matches_the_spec_example():
    # Same key schedule, so sealing the known file key reproduces the body.
    seed, enc, body = _vector()
    ss = _identity_decaps(seed, enc)
    assert xwing.seal_file_key(ss, enc, FILE_KEY) == body


def test_legacy_construction_is_not_the_spec():
    # The control: the construction 1.3.0 wrote does NOT open age's stanza...
    seed, enc, body = _vector()
    ss = _identity_decaps(seed, enc)
    with pytest.raises(Exception):
        xwing._open_legacy_file_key(ss, enc, body)
    # ...but a body it wrote still opens through open_file_key().
    hpke_ss = xwing.hpke_extract_and_expand(ss, enc)
    key, nonce = xwing.hpke_key_schedule_base(hpke_ss, b"")
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    legacy_body = ChaCha20Poly1305(key).encrypt(nonce, FILE_KEY, b"")
    assert legacy_body != body
    assert xwing.open_file_key(ss, enc, legacy_body) == FILE_KEY


def test_wrong_secret_fails_both():
    seed, enc, body = _vector()
    ss = bytearray(_identity_decaps(seed, enc))
    ss[0] ^= 1
    with pytest.raises(Exception):
        xwing.open_file_key(bytes(ss), enc, body)
