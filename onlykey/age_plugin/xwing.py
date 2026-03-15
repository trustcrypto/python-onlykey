"""X-Wing host-side cryptographic operations.

Implements the encryption-side (host) operations for X-Wing KEM
and the HPKE key schedule used by age's mlkem768x25519 stanza.

age's mlkem768x25519 stanza format:
  -> mlkem768x25519 <base64(1120-byte X-Wing ciphertext)>
  <base64(32-byte AEAD ciphertext)>

The body is ChaCha20-Poly1305(key, nonce, aad="", file_key)
where key and nonce come from the HPKE key schedule with X-Wing KEM.

HPKE cipher suite:
  KEM: X-Wing (ID 0x647a)
  KDF: HKDF-SHA256 (ID 0x0001)
  AEAD: ChaCha20-Poly1305 (ID 0x0003)
"""

import os
import hashlib
import hmac
import struct
from typing import Tuple

# Try cryptographic libraries
try:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey, X25519PublicKey,
    )
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


# HPKE constants for X-Wing cipher suite
HPKE_MODE_BASE = 0x00
KEM_ID = 0x647A     # X-Wing: 25519 + 203
KDF_ID = 0x0001     # HKDF-SHA256
AEAD_ID = 0x0003    # ChaCha20-Poly1305
N_SECRET = 32       # X-Wing shared secret size
N_H = 32            # HKDF-SHA256 hash output size
N_K = 32            # ChaCha20-Poly1305 key size
N_N = 12            # ChaCha20-Poly1305 nonce size

# suite_id for HPKE context
SUITE_ID_HPKE = b"HPKE" + struct.pack(">HHH", KEM_ID, KDF_ID, AEAD_ID)
SUITE_ID_KEM = b"KEM" + struct.pack(">H", KEM_ID)


def _i2osp(n: int, length: int) -> bytes:
    """Integer to Octet String Primitive (RFC 8017)."""
    return n.to_bytes(length, "big")


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract (RFC 5869)."""
    if not salt:
        salt = b"\x00" * 32
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand (RFC 5869)."""
    n = (length + 31) // 32
    okm = b""
    t = b""
    for i in range(1, n + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
    return okm[:length]


def _labeled_extract(salt: bytes, label: bytes, ikm: bytes,
                     suite_id: bytes) -> bytes:
    """HPKE LabeledExtract (RFC 9180 Section 4)."""
    labeled_ikm = b"HPKE-v1" + suite_id + label + ikm
    return _hkdf_extract(salt, labeled_ikm)


def _labeled_expand(prk: bytes, label: bytes, info: bytes,
                    length: int, suite_id: bytes) -> bytes:
    """HPKE LabeledExpand (RFC 9180 Section 4)."""
    labeled_info = _i2osp(length, 2) + b"HPKE-v1" + suite_id + label + info
    return _hkdf_expand(prk, labeled_info, length)


def hpke_extract_and_expand(shared_secret: bytes, kem_context: bytes) -> bytes:
    """HPKE ExtractAndExpand for KEM (RFC 9180 Section 4.1).

    Returns the HPKE shared_secret used in KeySchedule.
    """
    suite_id = SUITE_ID_KEM
    prk = _labeled_extract(b"", b"shared_secret", shared_secret, suite_id)
    return _labeled_expand(prk, b"context", kem_context, N_SECRET, suite_id)


def hpke_key_schedule_base(shared_secret: bytes, info: bytes,
                           psk: bytes = b"", psk_id: bytes = b""
                           ) -> Tuple[bytes, bytes]:
    """HPKE KeyScheduleBase (RFC 9180 Section 5.1).

    Returns (key, base_nonce) for AEAD.
    """
    mode = HPKE_MODE_BASE
    suite_id = SUITE_ID_HPKE

    psk_id_hash = _labeled_extract(b"", b"psk_id_hash", psk_id, suite_id)
    info_hash = _labeled_extract(b"", b"info_hash", info, suite_id)
    ks_context = bytes([mode]) + psk_id_hash + info_hash

    secret = _labeled_extract(shared_secret, b"secret", psk if psk else b"", suite_id)

    key = _labeled_expand(secret, b"key", ks_context, N_K, suite_id)
    base_nonce = _labeled_expand(secret, b"base_nonce", ks_context, N_N, suite_id)

    return key, base_nonce


def seal_file_key(shared_secret: bytes, enc: bytes, file_key: bytes,
                  info: bytes = b"") -> bytes:
    """HPKE SealBase: encrypt file key using X-Wing shared secret.

    Args:
        shared_secret: 32-byte X-Wing shared secret from Encaps
        enc: 1120-byte X-Wing ciphertext (used in kem_context)
        file_key: 16-byte file key to encrypt
        info: optional HPKE info parameter

    Returns:
        32-byte AEAD ciphertext (16 plaintext + 16 tag)
    """
    if not HAS_CRYPTO:
        raise RuntimeError("cryptography library required: pip install cryptography")

    # KEM context for X-Wing: just the enc (ciphertext)
    # For X-Wing, the kem_context is empty per the HPKE KEM interface
    # since X-Wing already binds ct_X and pk_X in its combiner
    kem_context = enc

    # ExtractAndExpand the KEM shared secret
    hpke_ss = hpke_extract_and_expand(shared_secret, kem_context)

    # Key schedule
    key, base_nonce = hpke_key_schedule_base(hpke_ss, info)

    # AEAD seal (seq=0, so nonce = base_nonce XOR 0 = base_nonce)
    aead = ChaCha20Poly1305(key)
    return aead.encrypt(base_nonce, file_key, b"")


def open_file_key(shared_secret: bytes, enc: bytes, ciphertext: bytes,
                  info: bytes = b"") -> bytes:
    """HPKE OpenBase: decrypt file key using X-Wing shared secret.

    Args:
        shared_secret: 32-byte X-Wing shared secret from Decaps
        enc: 1120-byte X-Wing ciphertext (used in kem_context)
        ciphertext: 32-byte AEAD ciphertext (16 plaintext + 16 tag)
        info: optional HPKE info parameter

    Returns:
        16-byte file key
    """
    if not HAS_CRYPTO:
        raise RuntimeError("cryptography library required: pip install cryptography")

    kem_context = enc
    hpke_ss = hpke_extract_and_expand(shared_secret, kem_context)
    key, base_nonce = hpke_key_schedule_base(hpke_ss, info)

    aead = ChaCha20Poly1305(key)
    return aead.decrypt(base_nonce, ciphertext, b"")


def x25519_keygen() -> Tuple[bytes, bytes]:
    """Generate X25519 keypair. Returns (private_key, public_key) as 32-byte each."""
    if not HAS_CRYPTO:
        raise RuntimeError("cryptography library required")
    sk = X25519PrivateKey.generate()
    pk = sk.public_key()
    sk_bytes = sk.private_bytes_raw()
    pk_bytes = pk.public_bytes_raw()
    return sk_bytes, pk_bytes


def x25519_scalarmult(sk: bytes, pk: bytes) -> bytes:
    """X25519 scalar multiplication."""
    if not HAS_CRYPTO:
        raise RuntimeError("cryptography library required")
    private = X25519PrivateKey.from_private_bytes(sk)
    public = X25519PublicKey.from_public_bytes(pk)
    return private.exchange(public)


def x25519_scalarmult_base(sk: bytes) -> bytes:
    """X25519 scalar multiplication with base point."""
    if not HAS_CRYPTO:
        raise RuntimeError("cryptography library required")
    private = X25519PrivateKey.from_private_bytes(sk)
    return private.public_key().public_bytes_raw()


# X-Wing label: "\./", "/^\" = hex 5c 2e 2f 2f 5e 5c
XWING_LABEL = bytes([0x5C, 0x2E, 0x2F, 0x2F, 0x5E, 0x5C])


def xwing_combiner(ss_m: bytes, ss_x: bytes, ct_x: bytes, pk_x: bytes) -> bytes:
    """X-Wing Combiner (draft-connolly-cfrg-xwing-kem-09 Section 5.3).

    SHA3-256(ss_M || ss_X || ct_X || pk_X || XWingLabel)
    """
    return hashlib.sha3_256(ss_m + ss_x + ct_x + pk_x + XWING_LABEL).digest()


def xwing_encaps_host(pk: bytes) -> Tuple[bytes, bytes]:
    """X-Wing Encapsulation (host-side, for encrypt).

    Args:
        pk: 1216-byte X-Wing public key (pk_M || pk_X)

    Returns:
        (shared_secret, ciphertext): 32 bytes, 1120 bytes

    NOTE: This requires a Python ML-KEM-768 implementation.
    For the initial version, this is a placeholder that raises
    NotImplementedError. The host-side encaps can be added when
    a suitable ML-KEM Python library is integrated.
    """
    # Parse PK: pk_M(1184) || pk_X(32)
    pk_m = pk[:1184]
    pk_x = pk[1184:1216]

    # X25519: ek_X = random, ct_X = X25519(ek_X, BASE), ss_X = X25519(ek_X, pk_X)
    ek_x_bytes, ct_x = x25519_keygen()  # ek is random, ct_x = pub
    # Actually: ek_X = random(32), ct_X = X25519(ek_X, BASE), ss_X = X25519(ek_X, pk_X)
    ek_x = os.urandom(32)
    ct_x = x25519_scalarmult_base(ek_x)
    ss_x = x25519_scalarmult(ek_x, pk_x)

    # ML-KEM-768: (ss_M, ct_M) = ML-KEM-768.Encaps(pk_M)
    from onlykey.age_plugin.mlkem_py import mlkem768_encaps
    ss_m, ct_m = mlkem768_encaps(pk_m)

    # Combiner
    ss = xwing_combiner(ss_m, ss_x, ct_x, pk_x)

    # Ciphertext: ct_M(1088) || ct_X(32)
    ct = ct_m + ct_x

    return ss, ct
