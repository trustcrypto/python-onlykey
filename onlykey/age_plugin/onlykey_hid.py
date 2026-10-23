"""OnlyKey USB HID communication for ML-KEM-768 and X-Wing KEM.

Uses the existing onlykey.client.OnlyKey class for HID transport,
with support for multi-packet payloads needed for post-quantum key sizes.

Slots:
  133 (RESERVED_KEY_MLKEM)  - ML-KEM-768 standalone
  134 (RESERVED_KEY_XWING)  - X-Wing hybrid KEM
"""

import hashlib
import sys
import time

from onlykey.client import OnlyKey, Message
# The challenge rule and the error classifier come from the generated
# protocol module - one source for host and firmware. derived_recipient_payload
# and derived_decaps_payload are NOT imported: they frame the host-split
# X-Wing exchange, and this plugin uses the device-custody one (see
# derive_recipient below), so importing them would be dead weight that reads
# like the two designs are both live.
from onlykey.protocol import challenge_code_str, classify_response
from .protocol import notify
from . import (
    OKGETPUBKEY, OKDECRYPT, OKSETPRIV, GENERATE_ON_DEVICE,
    DEFAULT_MLKEM_SLOT, DEFAULT_XWING_SLOT,
    KEYTYPE_MLKEM768, KEYTYPE_XWING, RESERVED_KEY_WEB_DERIVATION,
    validate_ecc_slot,
)

# Sizes
XWING_PK_SIZE = 1216
XWING_CT_SIZE = 1120
XWING_SS_SIZE = 32
MLKEM_PK_SIZE = 1184
MLKEM_CT_SIZE = 1088
DERIVED_LABEL_TAG_SIZE = 32


def derived_challenge_code_str(request: bytes, duo: bool = False) -> str:
    """The 3 digits the device shows for a DERIVED request, as "n n n".

    Two hashes, and the reason is that they happen in two different places.
    okcore_prime_user_confirmation() hashes whatever it is PRIMED with and
    takes bytes 0, 15, 31 modulo the button count - that rule lives once, in
    the generated protocol module, as challenge_code_str(). But for a derived
    operation the value it is primed with is itself SHA256(label_tag || ct),
    computed in okcrypto.cpp before the confirmation is raised. So the caller
    holds the raw request, and this hashes it once to get what the device was
    primed with, then hands that to the shared rule.

    NAMED DIFFERENTLY ON PURPOSE. This file used to define its own
    `challenge_code_str` doing both hashes inline, which SHADOWED the import
    of the shared one - same name, different input contract (local(x) ==
    shared(sha256(x)), verified across five vectors). It produced the right
    digits only because the local definition came after the import and the
    callers happened to match its contract. Anyone deleting the "duplicate"
    would have silently started displaying the wrong code, and a wrong code in
    challenge mode is `Error incorrect challenge was entered` - the failure
    that cost a day on 2026-09-16. One rule, two names, no shadowing.
    """
    return challenge_code_str(hashlib.sha256(bytes(request)).digest(), duo)


def derived_label_tag(label):
    """32-byte derivation tag for a derived-identity label.

    This is the value the firmware folds into HKDF as ``additional_data`` and
    MUST be produced identically by the web app for the same logical identity,
    otherwise the two derive different keys and files won't cross-decrypt.
    Convention: SHA256(utf8(label)).
    """
    return hashlib.sha256(label.encode("utf-8")).digest()


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
            except RuntimeError:
                # A device-reported condition ("Timeout occured while waiting
                # for confirmation on OnlyKey", "OnlyKey is locked", ...).
                # read_bytes() raises RuntimeError *only* for these - a plain
                # read timeout returns an empty list and is handled by the
                # `if not data` below. So this must propagate: swallowing it
                # turned "you did not press the button" into a bare
                # "got 0 bytes, expected N" protocol failure, which is what
                # it looked like on hardware 2026-09-15 while the firmware
                # had been answering correctly the whole time.
                raise
            except Exception:
                # A single read timing out mid-stream doesn't mean the
                # device is done sending - keep polling until the real
                # deadline. Bailing out early here (as soon as `result` was
                # non-empty) was truncating multi-packet responses like the
                # 1216-byte X-Wing pubkey whenever one 2s read happened to
                # time out before the next packet arrived.
                continue
            if not data:
                continue
            kind, text = classify_response(data)
            if kind == "error":
                raise RuntimeError(f"OnlyKey: {text.strip()}")
            result.extend(data)
            if expected_size and len(result) >= expected_size:
                break

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
        notify("Press OnlyKey button to confirm decryption...")
        self.ok.send_large_message2(
            msg=Message(OKDECRYPT), payload=list(ciphertext), slot_id=slot,
        )
        return self._read_response(expected_size=32, timeout_ms=30000)

    def xwing_keygen(self, slot=DEFAULT_XWING_SLOT):
        """Generate an X-Wing keypair in the given ECC slot. Returns 1216-byte pubkey."""
        slot = validate_ecc_slot(slot)
        notify("Press OnlyKey button to confirm key generation...")
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

    # ---- Derived (label-based) X-Wing ------------------------------------
    # No key is stored; the device derives the whole X-Wing keypair from
    # (web-and-agent derivation key, tag) on demand and keeps both
    # halves. This is the path that interoperates with the web app: same
    # OnlyKey + same tag => same key.
    #
    # It used to be split custody - the device returned a 32-byte ML-KEM seed
    # and the host expanded it, ran ML-KEM decapsulation and combined the
    # halves. The seed is private key material (it yields sk_M), so a request
    # for a public key was answered with a private one, and the ML-KEM half of
    # a hardware key actually lived in this process. Both calls below changed
    # shape to fix that; derived_xwing.py's split helpers went with it.

    def derive_recipient(self, label):
        """Derived X-Wing recipient over HID. Returns the 1216-byte public key.

        Single-report request - the 32-byte tag fits one report - with a
        chunked response: XWING_PK_SIZE is pk_M(1184) || pk_X(32), which the
        firmware stages in large_resp_buffer and serves in pieces.

        This returned [pk_X(32) | mlkem_seed(32)] before, and the caller built
        the recipient locally. ML-KEM has no short public key - the only
        32-byte value that reproduces pk_M also reproduces sk_M - so there is
        no way to send a public key compactly; the public key itself is what
        crosses the wire.
        """
        tag = derived_label_tag(label)
        resp = self._send_and_receive(
            OKGETPUBKEY, RESERVED_KEY_WEB_DERIVATION, payload=tag,
            key_type=KEYTYPE_XWING, expected_size=XWING_PK_SIZE,
            timeout_ms=10000,
        )
        if len(resp) != XWING_PK_SIZE:
            raise RuntimeError(
                f"derived recipient: got {len(resp)} bytes, expected {XWING_PK_SIZE}"
            )
        return resp

    def derive_decaps(self, label, ciphertext):
        """Derived X-Wing decapsulation over HID. Returns the 32-byte shared secret.

        Sends [tag(32) || ct(1120)] = 1152 B via the multi-packet path and gets
        the finished X-Wing shared secret back. The device does both halves.

        Previously this sent [tag(32) || ct_X(32)] and got back
        [ss_X(32) | mlkem_seed(32)], leaving the ML-KEM half to the host: ct_M
        never reached the device and the seed always reached the host. Both are
        reversed now, so the derived path custodies its whole key exactly as
        the stored path does.
        """
        if len(ciphertext) != XWING_CT_SIZE:
            raise ValueError(
                f"X-Wing ct must be {XWING_CT_SIZE} bytes, got {len(ciphertext)}"
            )
        tag = derived_label_tag(label)
        # The device gates this per field 30 (web-and-agent derive mode):
        # 1 = press (default), 0 = type this 3-digit code on the device,
        # 2 = no prompt. We cannot read the setting back, so show both -
        # and the code has to be shown, because in challenge mode there is
        # nothing on the device telling the user what to type.
        notify(
            "Confirm on OnlyKey: press any button, or if it is set to "
            "challenge-code mode enter %s" % derived_challenge_code_str(tag + bytes(ciphertext))
        )
        self.ok.send_large_message2(
            msg=Message(OKDECRYPT), payload=list(tag + bytes(ciphertext)),
            slot_id=RESERVED_KEY_WEB_DERIVATION,
        )
        resp = self._read_response(expected_size=XWING_SS_SIZE, timeout_ms=30000)
        if len(resp) != XWING_SS_SIZE:
            raise RuntimeError(
                f"derived decaps: got {len(resp)} bytes, expected {XWING_SS_SIZE}"
            )
        return resp

    def mlkem_keygen(self, slot=DEFAULT_MLKEM_SLOT):
        """Generate an ML-KEM-768 keypair in the given ECC slot. Returns 1184-byte pubkey."""
        slot = validate_ecc_slot(slot)
        notify("Press OnlyKey button to confirm key generation...")
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
