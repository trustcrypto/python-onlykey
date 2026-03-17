"""Post-quantum cryptographic helpers for OnlyKey.

Canonical location for X-Wing (ML-KEM-768 + X25519) helper types and
utilities used by downstream projects (lib-agent, onlykey-a2a-bridge,
onlykey-agent-skills).

The low-level HID transport lives in onlykey.age_plugin.onlykey_hid.OnlyKeyPQ.
The host-side X-Wing encapsulation lives in onlykey.age_plugin.xwing.
This module provides the higher-level helpers that sit on top of both.

Usage::

    from onlykey.pq import (
        xwing_fingerprint,
        xwing_encaps,
        derive_session_key,
        PQPublicInfo,
    )

    # Fingerprint a public key (8-byte SHA-256 prefix)
    fp = xwing_fingerprint(pk)

    # Encapsulate a shared secret (host-side, no device needed)
    ss, ct = xwing_encaps(recipient_pk)

    # Derive a session key from a shared secret
    key = derive_session_key(ss, context=b"my-app-v1")

    # Serialize public key info for wire/storage
    info = PQPublicInfo.from_raw(pk)
    d = info.to_dict()
    info2 = PQPublicInfo.from_dict(d)
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Tuple

# Re-export constants from the HID module
from onlykey.age_plugin.onlykey_hid import (
    XWING_PK_SIZE,
    XWING_CT_SIZE,
    XWING_SS_SIZE,
)

__all__ = [
    "XWING_PK_SIZE",
    "XWING_CT_SIZE",
    "XWING_SS_SIZE",
    "XWING_FINGERPRINT_LEN",
    "xwing_fingerprint",
    "xwing_encaps",
    "derive_session_key",
    "PQPublicInfo",
]

# Fingerprint: first 8 bytes of SHA-256(public_key)
XWING_FINGERPRINT_LEN = 8


def xwing_fingerprint(pk: bytes) -> bytes:
    """Compute a short fingerprint of an X-Wing public key.

    Used for identity binding — the fingerprint can be embedded in
    age identity strings or Agent Card extensions to verify that the
    correct device is being used.

    Args:
        pk: 1216-byte X-Wing public key.

    Returns:
        8-byte SHA-256 fingerprint.
    """
    if len(pk) != XWING_PK_SIZE:
        raise ValueError(
            f"X-Wing public key must be {XWING_PK_SIZE} bytes, got {len(pk)}"
        )
    return hashlib.sha256(pk).digest()[:XWING_FINGERPRINT_LEN]


def xwing_encaps(recipient_pk: bytes) -> Tuple[bytes, bytes]:
    """Encapsulate a shared secret against an X-Wing public key.

    Host-side operation — no OnlyKey device needed. Generates a random
    ephemeral key and computes the X-Wing KEM encapsulation.

    This is a convenience wrapper around
    ``onlykey.age_plugin.xwing.xwing_encaps_host``.

    Args:
        recipient_pk: 1216-byte X-Wing public key.

    Returns:
        Tuple of (shared_secret, ciphertext):
          - shared_secret: 32-byte shared secret
          - ciphertext: 1120-byte X-Wing ciphertext to send to recipient
    """
    if len(recipient_pk) != XWING_PK_SIZE:
        raise ValueError(
            f"Recipient public key must be {XWING_PK_SIZE} bytes, "
            f"got {len(recipient_pk)}"
        )
    from onlykey.age_plugin.xwing import xwing_encaps_host
    return xwing_encaps_host(recipient_pk)


def derive_session_key(
    shared_secret: bytes,
    context: bytes = b"onlykey-pq-v1",
    key_len: int = 32,
) -> bytes:
    """Derive a session key from an X-Wing shared secret using HKDF-SHA256.

    For non-age use cases (A2A channels, MCP tool encryption, etc.) where
    callers need a session key rather than an age file key.

    Args:
        shared_secret: 32-byte X-Wing shared secret from encaps/decaps.
        context: Application context bytes for domain separation.
            Different applications MUST use different context strings.
        key_len: Desired output key length (default 32).

    Returns:
        Derived key bytes.
    """
    if len(shared_secret) != XWING_SS_SIZE:
        raise ValueError(
            f"Shared secret must be {XWING_SS_SIZE} bytes, "
            f"got {len(shared_secret)}"
        )

    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=key_len,
        salt=None,
        info=context,
    )
    return hkdf.derive(shared_secret)


@dataclass(frozen=True)
class PQPublicInfo:
    """Serializable container for an X-Wing public key and its fingerprint.

    Used when exchanging PQ key material between agents (Agent Cards,
    MCP tool configuration, etc.).

    Attributes:
        public_key: 1216-byte X-Wing public key.
        fingerprint: 8-byte SHA-256 fingerprint.
    """

    public_key: bytes
    fingerprint: bytes

    def __post_init__(self) -> None:
        if len(self.public_key) != XWING_PK_SIZE:
            raise ValueError(
                f"X-Wing public key must be {XWING_PK_SIZE} bytes, "
                f"got {len(self.public_key)}"
            )
        if len(self.fingerprint) != XWING_FINGERPRINT_LEN:
            raise ValueError(
                f"Fingerprint must be {XWING_FINGERPRINT_LEN} bytes, "
                f"got {len(self.fingerprint)}"
            )

    @classmethod
    def from_raw(cls, pk: bytes) -> PQPublicInfo:
        """Create from a raw public key, computing the fingerprint."""
        return cls(public_key=pk, fingerprint=xwing_fingerprint(pk))

    @classmethod
    def from_device(cls, device) -> PQPublicInfo:
        """Read PQ public info from a connected OnlyKey device.

        Works with any object that has an ``xwing_getpubkey()`` method:
          - ``onlykey.age_plugin.onlykey_hid.OnlyKeyPQ``
          - ``libagent.age.client.Client``
          - ``onlykey_a2a.crypto.device.OnlyKeyDevice``

        Args:
            device: Object with ``xwing_getpubkey() -> bytes`` method.
        """
        pk = device.xwing_getpubkey()
        return cls.from_raw(pk)

    def verify_fingerprint(self) -> bool:
        """Check that the fingerprint matches the public key."""
        return self.fingerprint == xwing_fingerprint(self.public_key)

    def to_dict(self) -> dict[str, str]:
        """Serialize for JSON/Agent Card/wire format."""
        return {
            "algorithm": "X-Wing",
            "kem": "mlkem768x25519",
            "public_key_hex": self.public_key.hex(),
            "fingerprint_hex": self.fingerprint.hex(),
            "pk_size": str(XWING_PK_SIZE),
        }

    @classmethod
    def from_dict(cls, data: dict[str, str]) -> PQPublicInfo:
        """Deserialize from JSON/Agent Card/wire format."""
        pk = bytes.fromhex(data["public_key_hex"])
        fp = bytes.fromhex(data["fingerprint_hex"])
        return cls(public_key=pk, fingerprint=fp)
