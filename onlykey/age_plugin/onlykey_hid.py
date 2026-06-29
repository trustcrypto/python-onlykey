"""OnlyKey USB HID communication for ML-KEM-768 and X-Wing KEM.

Uses the existing onlykey.client.OnlyKey class for HID transport,
with support for multi-packet payloads needed for post-quantum key sizes.

Slots:
  133 (RESERVED_KEY_MLKEM)  - ML-KEM-768 standalone
  134 (RESERVED_KEY_XWING)  - X-Wing hybrid KEM
"""

import sys
import time

from onlykey.client import OnlyKey, Message
from . import (
    OKGETPUBKEY, OKDECRYPT, OKSETPRIV, GENERATE_ON_DEVICE,
    DEFAULT_MLKEM_SLOT, DEFAULT_XWING_SLOT,
    KEYTYPE_MLKEM768, KEYTYPE_XWING, validate_ecc_slot,
)

# Sizes
XWING_PK_SIZE = 1216
XWING_CT_SIZE = 1120
XWING_SS_SIZE = 32
MLKEM_PK_SIZE = 1184
MLKEM_CT_SIZE = 1088


class OnlyKeyPQ:
    """Post-quantum KEM interface to OnlyKey hardware."""

    def __init__(self, ok=None):
        """Initialize with existing OnlyKey instance or create new one.

        Args:
            ok: Existing OnlyKey instance, or None to create one.
        """
        if ok is not None:
            self.ok = ok
        else:
            self.ok = OnlyKey()
            self._connect()

    def _connect(self):
        """Connect to OnlyKey device."""
        try:
            self.ok.read_string(timeout_ms=100)
        except Exception:
            pass
        for _ in range(10):
            try:
                self.ok.read_string(timeout_ms=500)
                return
            except Exception:
                time.sleep(0.5)
        raise RuntimeError("Could not connect to OnlyKey. Is it plugged in and unlocked?")

    def _send_and_receive(self, msg_type, slot, payload=b"", key_type=None,
                          expected_size=0, timeout_ms=10000):
        """Send a SINGLE-packet request and collect the response.

        Wire layout expected by firmware: buffer[5]=slot, buffer[6]=key type,
        buffer[7:]=payload. ``key_type`` is placed in buffer[6] so the device
        routes the request to the ML-KEM / X-Wing handler for the ECC slot.

        This is only valid when the request payload fits in one 64-byte report
        (keygen trigger, getpubkey). Large inputs that exceed one report — the
        decapsulation ciphertext — must use the multi-packet send path; see
        ``*_decaps`` below.
        """
        body = bytearray()
        if key_type is not None:
            body.append(key_type & 0x0F)   # firmware buffer[6]
        body.extend(payload)
        self.ok.send_message(msg=Message(msg_type), slot_id=slot, payload=body)
        return self._read_response(expected_size=expected_size, timeout_ms=timeout_ms)

    def _read_response(self, expected_size=0, timeout_ms=10000):
        """Collect a (possibly multi-packet) response from the device."""
        result = bytearray()
        deadline = time.time() + timeout_ms / 1000
        while time.time() < deadline:
            try:
                data = self.ok.read_bytes(64, timeout_ms=2000)
                if data:
                    text = bytes(data).decode("ascii", errors="ignore")
                    if text.startswith("Error"):
                        raise RuntimeError(f"OnlyKey: {text.strip()}")
                    result.extend(data)
                    if expected_size and len(result) >= expected_size:
                        break
            except Exception:
                if result:
                    break
                continue

        return bytes(result[:expected_size] if expected_size else result)

    def _decaps(self, ciphertext, slot):
        """Send a KEM ciphertext for on-device decapsulation; return 32-byte SS.

        The ciphertext (1088 B for ML-KEM, 1120 B for X-Wing) is far larger than
        one 64-byte HID report, so it is streamed with the multi-packet protocol
        (``send_large_message2``) — the same path the OnlyKey CLI uses to send
        RSA/ECDH ciphertext for OKDECRYPT. Each packet carries
        [slot, 0xFF-or-final-length, <=57 bytes], which the firmware accumulates
        into its large buffer. The device reads the key TYPE from the key stored
        in ``slot`` (not from the packet), waits for a button press, then returns
        the 32-byte shared secret.
        """
        print("Press OnlyKey button to confirm decryption...", file=sys.stderr)
        self.ok.send_large_message2(
            msg=Message(OKDECRYPT), payload=list(ciphertext), slot_id=slot,
        )
        return self._read_response(expected_size=32, timeout_ms=30000)

    def xwing_keygen(self, slot=DEFAULT_XWING_SLOT):
        """Generate an X-Wing keypair in the given ECC slot. Returns 1216-byte pubkey."""
        slot = validate_ecc_slot(slot)
        print("Press OnlyKey button to confirm key generation...", file=sys.stderr)
        pk = self._send_and_receive(
            OKSETPRIV, slot,
            payload=GENERATE_ON_DEVICE, key_type=KEYTYPE_XWING,
            expected_size=XWING_PK_SIZE,
            timeout_ms=30000,
        )
        if len(pk) != XWING_PK_SIZE:
            raise RuntimeError(f"X-Wing keygen: got {len(pk)} bytes, expected {XWING_PK_SIZE}")
        return pk

    def xwing_getpubkey(self, slot=DEFAULT_XWING_SLOT):
        """Get the X-Wing public key from the given ECC slot. Returns 1216-byte pubkey."""
        slot = validate_ecc_slot(slot)
        pk = self._send_and_receive(
            OKGETPUBKEY, slot, key_type=KEYTYPE_XWING,
            expected_size=XWING_PK_SIZE,
            timeout_ms=10000,
        )
        if len(pk) != XWING_PK_SIZE:
            raise RuntimeError(f"X-Wing getpubkey: got {len(pk)} bytes, expected {XWING_PK_SIZE}")
        return pk

    def xwing_decaps(self, ciphertext, slot=DEFAULT_XWING_SLOT):
        """X-Wing decapsulation in the given ECC slot. Returns 32-byte shared secret."""
        slot = validate_ecc_slot(slot)
        if len(ciphertext) != XWING_CT_SIZE:
            raise ValueError(f"X-Wing CT must be {XWING_CT_SIZE} bytes, got {len(ciphertext)}")
        ss = self._decaps(ciphertext, slot)
        if len(ss) != XWING_SS_SIZE:
            raise RuntimeError(f"X-Wing decaps: got {len(ss)} bytes, expected {XWING_SS_SIZE}")
        return ss

    def mlkem_keygen(self, slot=DEFAULT_MLKEM_SLOT):
        """Generate an ML-KEM-768 keypair in the given ECC slot. Returns 1184-byte pubkey."""
        slot = validate_ecc_slot(slot)
        print("Press OnlyKey button to confirm key generation...", file=sys.stderr)
        return self._send_and_receive(
            OKSETPRIV, slot,
            payload=GENERATE_ON_DEVICE, key_type=KEYTYPE_MLKEM768,
            expected_size=MLKEM_PK_SIZE,
            timeout_ms=30000,
        )

    def mlkem_getpubkey(self, slot=DEFAULT_MLKEM_SLOT):
        """Get the ML-KEM-768 public key from the given ECC slot. Returns 1184-byte pubkey."""
        slot = validate_ecc_slot(slot)
        return self._send_and_receive(
            OKGETPUBKEY, slot, key_type=KEYTYPE_MLKEM768,
            expected_size=MLKEM_PK_SIZE,
            timeout_ms=10000,
        )

    def mlkem_decaps(self, ciphertext, slot=DEFAULT_MLKEM_SLOT):
        """ML-KEM-768 decapsulation in the given ECC slot. Returns 32-byte shared secret."""
        slot = validate_ecc_slot(slot)
        if len(ciphertext) != MLKEM_CT_SIZE:
            raise ValueError(f"ML-KEM CT must be {MLKEM_CT_SIZE} bytes, got {len(ciphertext)}")
        return self._decaps(ciphertext, slot)
