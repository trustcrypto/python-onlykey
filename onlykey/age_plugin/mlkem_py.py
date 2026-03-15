"""ML-KEM-768 Python wrapper for host-side operations.

Uses kyber-py (pip install kyber-py) for FIPS 203 ML-KEM-768.
This module provides encapsulation only — decapsulation happens
on the OnlyKey hardware device.
"""

from kyber_py.ml_kem import ML_KEM_768


def mlkem768_encaps(ek: bytes) -> tuple[bytes, bytes]:
    """ML-KEM-768 encapsulation (host-side).

    Args:
        ek: 1184-byte ML-KEM-768 encapsulation (public) key

    Returns:
        (ss, ct): 32-byte shared secret and 1088-byte ciphertext
    """
    if len(ek) != 1184:
        raise ValueError(f"ML-KEM-768 EK must be 1184 bytes, got {len(ek)}")
    ss, ct = ML_KEM_768.encaps(ek)
    return ss, ct


def mlkem768_keygen() -> tuple[bytes, bytes]:
    """ML-KEM-768 key generation (for testing only).

    Returns:
        (ek, dk): 1184-byte encapsulation key and 2400-byte decapsulation key
    """
    ek, dk = ML_KEM_768.keygen()
    return ek, dk


def mlkem768_decaps(dk: bytes, ct: bytes) -> bytes:
    """ML-KEM-768 decapsulation (for testing only — production uses OnlyKey).

    Args:
        dk: 2400-byte decapsulation (secret) key
        ct: 1088-byte ciphertext

    Returns:
        32-byte shared secret
    """
    if len(dk) != 2400:
        raise ValueError(f"ML-KEM-768 DK must be 2400 bytes, got {len(dk)}")
    if len(ct) != 1088:
        raise ValueError(f"ML-KEM-768 CT must be 1088 bytes, got {len(ct)}")
    return ML_KEM_768.decaps(dk, ct)
