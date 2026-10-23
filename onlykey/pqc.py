"""
onlykey/pqc.py — composite post-quantum PGP keys over the USB-HID transport.

Matches the firmware in trustcrypto/libraries PR #31 (KEYTYPE_PQC_PGP = 7):
one RSA slot (1-4) holds one composite key as a 160-byte seed blob, and the
device does ML-KEM-768 decapsulation + ML-DSA-65 signing on-device.

This is the CLI/agent path (loaded keys, HID transport). It is NOT the
age/X-Wing *derive* path (that is firmware + web app over FIDO2).

Wire protocol (as implemented by okpqc.cpp):
  * Load  : OKSETPRIV, slot, key_type = 0x67 (KEYTYPE_PQC_PGP | decrypt bit5 | sign bit6),
            payload = 160-byte blob.
  * Decrypt (OKDECRYPT, slot): the device picks the half by INPUT SIZE:
            32-byte X25519 ephemeral point -> X25519 shared secret (32 B)
            1088-byte ML-KEM ciphertext    -> ML-KEM shared secret (32 B)
  * Sign  (OKSIGN, slot): payload = [selector_byte] + digest, selector:
            0 = Ed25519 (-> 64-byte sig),  1 = ML-DSA-65 (-> 3309-byte sig)

Composite blob layout (160 bytes):
  [0:32]  Ed25519 secret       (sign, ecc half)
  [32:64] ML-DSA-65 seed       (sign, pqc half)     FIPS 204 32-byte seed
  [64:96] X25519 secret        (decrypt, ecc half)
  [96:160] ML-KEM-768 seed     (decrypt, pqc half)  FIPS 203 64-byte seed (d||z)

Every operation here raises the device's three-button confirmation: okpqc_sign()
and okpqc_decrypt() both prime on their first call and do nothing at all until
CRYPTO_AUTH reaches 4. The caller sends once and then waits — the firmware
re-runs the operation itself from the third button press (OnlyKey.ino's
OKSIGN/OKDECRYPT branches), so the request is NOT resent.

Exercise status, because the two halves differ. The LOAD path - the chunked
OKSETPRIV send in load_composite_key() - has run against a physical OnlyKey via
`onlykey-cli loadpqc`. The binary READ path below (read_exact, and therefore
sign() and decrypt()) has been exercised against an emulated device only; it has
not yet run against hardware.
"""
import time

from .client import Message, MAX_INPUT_REPORT_SIZE

# --- key type + layout (mirror okpqc.h) ---------------------------------------
KEYTYPE_PQC_PGP   = 7
FEATURE_DECRYPT   = 0x20   # bit 5
FEATURE_SIGN      = 0x40   # bit 6
PQC_KEY_TYPE_BYTE = KEYTYPE_PQC_PGP | FEATURE_DECRYPT | FEATURE_SIGN   # 0x67

PQC_PGP_BLOB_LEN  = 160
OFF_ED25519       = 0
OFF_MLDSA_SEED    = 32
OFF_X25519        = 64
OFF_MLKEM_SEED    = 96

ED25519_SK_LEN    = 32
MLDSA_SEED_LEN    = 32
X25519_SK_LEN     = 32
MLKEM_SEED_LEN    = 64

# component selector (sign only; decrypt infers from size)
HALF_ECC = 0
HALF_PQC = 1

# transport sizes
MLKEM_CT_LEN  = 1088
X25519_PT_LEN = 32
SS_LEN        = 32
ED25519_SIG_LEN = 64
MLDSA_SIG_LEN   = 3309


def build_composite_blob(ed25519_sk, mldsa_seed, x25519_sk, mlkem_seed):
    """Pack the four private seeds into the 160-byte composite blob."""
    for name, val, ln in (
        ("ed25519_sk", ed25519_sk, ED25519_SK_LEN),
        ("mldsa_seed", mldsa_seed, MLDSA_SEED_LEN),
        ("x25519_sk",  x25519_sk,  X25519_SK_LEN),
        ("mlkem_seed", mlkem_seed, MLKEM_SEED_LEN),
    ):
        if len(val) != ln:
            raise ValueError("%s must be %d bytes, got %d" % (name, ln, len(val)))
    blob = bytes(ed25519_sk) + bytes(mldsa_seed) + bytes(x25519_sk) + bytes(mlkem_seed)
    assert len(blob) == PQC_PGP_BLOB_LEN
    return blob


def load_composite_key(ok, slot, blob):
    """Load a composite PQC PGP key (160-byte seed blob) into RSA slot 1-4.

    Uses OKSETPRIV with key_type = 0x67 (PQC composite; decrypt+sign capable),
    the same op RSA keys use. Only allowed in config mode / first use.
    """
    if not 1 <= slot <= 4:
        raise ValueError("PQC composite keys use RSA slots 1-4")
    if len(blob) != PQC_PGP_BLOB_LEN:
        raise ValueError("blob must be %d bytes" % PQC_PGP_BLOB_LEN)
    # The firmware OKSETPRIV reads buffer[5]=slot, buffer[6]=key_type, buffer[7:]=57-byte chunk,
    # accumulating across messages. send_message frames [hdr][msg][slot_id][payload], so each
    # payload = [key_type] + 57-byte chunk puts key_type at buffer[6] and data at buffer[7:].
    blob = bytes(blob)
    for i in range(0, PQC_PGP_BLOB_LEN, 57):
        chunk = blob[i:i + 57]
        # send_message accepts str(hex)/list/bytearray/int — NOT bytes — so frame
        # the payload as a bytearray: [key_type] + 57-byte chunk (key_type -> buffer[6]).
        ok.send_message(msg=Message.OKSETPRIV, slot_id=slot,
                        payload=bytearray([PQC_KEY_TYPE_BYTE]) + bytearray(chunk))

    _await_load_reply(ok)


# rsa_priv_flash()'s acknowledgement, printed once the accumulated chunks reach
# the declared key size. The composite branch declares 160.
_LOAD_OK = "Successfully set RSA Key"


def _await_load_reply(ok, timeout_ms=6000):
    """Require the device to acknowledge the load, and raise if it refused.

    Without this the load is unverifiable from the host: okcrypto_getpubkey()
    has no KEYTYPE_PQC_PGP branch, so a composite key cannot be read back, and
    the only other evidence is asking the device to sign - which needs a button
    press and so cannot be part of a load call.

    It matters most for the refusal that is easy to hit by accident. OKSETPRIV
    is permitted only in config mode or on first use, and outside it the device
    answers "Error not in config mode" to each of the three chunks. A caller
    that does not read those replies cannot distinguish a stored key from an
    empty slot, and will report success for a load that did nothing.
    """
    seen = []
    last_error = None
    deadline = time.time() + timeout_ms / 1000.0
    while time.time() < deadline:
        try:
            data = ok.read_bytes(MAX_INPUT_REPORT_SIZE, to_bytes=True, timeout_ms=500)
        except Exception as e:
            # read_bytes() raises for a locked or uninitialised device and for
            # several named device errors - each of those is a refused load -
            # but it can also throw transiently on the read itself. Keep
            # polling and report this only if nothing conclusive arrives, so a
            # blip cannot fail a load that actually succeeded.
            last_error = e
            continue
        if not data:
            continue
        text = bytes(data).split(b"\x00")[0].decode("ascii", "ignore").strip()
        if not text:
            continue
        seen.append(text)
        if text.startswith("Error"):
            raise RuntimeError("OnlyKey refused the key load: %s" % text)
        if _LOAD_OK in text:
            return text

    if last_error is not None and not seen:
        raise RuntimeError("OnlyKey: %s" % last_error)
    raise RuntimeError(
        "OnlyKey did not acknowledge the key load (expected %r, saw %r)"
        % (_LOAD_OK, seen))


# Status broadcasts the device emits on its own schedule. A single read taken
# right after OKSIGN/OKDECRYPT gets whichever report is first, which is how the
# ASCII of "UNLOCKED" ends up where a signature belongs.
_STATUS_PREFIXES = (b"UNLOCKED", b"INITIALIZED", b"UNINITIALIZED")


def read_exact(ok, want, timeout_ms=30000):
    """Read exactly ``want`` bytes of BINARY response, reassembled across reports.

    ``read_string()`` cannot be used for any of this, for two independent
    reasons, and neither is a matter of probability:

      * it is ``''.join(chr(b) for b in ... if b != 0)`` — it DROPS EVERY ZERO
        BYTE and returns str, so any signature or shared secret containing a
        0x00 comes back short and shifted; and
      * ``read_bytes()`` underneath it is a SINGLE ``self._hid.read(n)`` with no
        reassembly, and ``read_string()`` calls it with MAX_INPUT_REPORT_SIZE —
        one report — so ``read_string(...)[:3309]`` for an ML-DSA-65 signature
        is impossible by construction rather than merely unreliable: one
        report's worth is the most it can ever return.

    The device sends a large response as consecutive 64-byte reports in one
    tight loop (``send_transport_response()``, okcore.cpp, ``outputmode == 0``),
    so a 3309-byte signature arrives as 52 reports and nothing interleaves with
    them. This is the same collect-until-expected-size loop the age plugin's
    ``OnlyKeyPQ._read_response()`` uses for the 1216-byte X-Wing pubkey, with
    one addition it does not need: leading status broadcasts are skipped.

    Skipping is deliberately confined to the reports BEFORE the first data byte.
    Once the response has started, a report may legitimately be all zeros or
    read as text, and dropping one of those would silently corrupt the result.

    ``read_string()`` is deliberately left alone rather than fixed in place:
    every other subcommand in the CLI depends on its current behaviour.
    """
    out = bytearray()
    started = False
    last_error = None
    deadline = time.time() + timeout_ms / 1000.0
    while time.time() < deadline and len(out) < want:
        try:
            data = ok.read_bytes(MAX_INPUT_REPORT_SIZE, to_bytes=True, timeout_ms=2000)
        except Exception as e:
            # A read timing out mid-stream does not mean the device is done;
            # keep going to the real deadline. read_bytes() also raises for a
            # locked/uninitialised device, which is worth reporting if nothing
            # ever arrives - so remember it rather than discarding it.
            last_error = e
            continue
        if not data:
            continue
        data = bytes(data)
        if data.startswith(b"Error"):
            raise RuntimeError("OnlyKey: %s" % data.split(b"\x00")[0].decode("ascii", "ignore").strip())
        if not started:
            if data.startswith(_STATUS_PREFIXES) or not any(data):
                continue
            started = True
        out.extend(data)

    if len(out) < want:
        if not started and last_error is not None:
            raise last_error
        raise RuntimeError("OnlyKey: got %d of %d bytes" % (len(out), want))
    return bytes(out[:want])


def decrypt(ok, slot, data, timeout_ms=None):
    """Composite decrypt. Send either the 32-byte X25519 ephemeral point (ECC half)
    or the 1088-byte ML-KEM ciphertext (PQC half); the device picks by size and
    returns the 32-byte shared secret as BYTES. The caller does the SHA3-256 key
    combine + RFC 3394 AES key-unwrap (openpgp.js's kem.js does this for the web
    app); see draft-ietf-openpgp-pqc-10 section 4.2.1 for the combiner.

    Raises the three-button confirmation on the device."""
    if len(data) not in (X25519_PT_LEN, MLKEM_CT_LEN):
        raise ValueError("decrypt input must be %d (X25519 point) or %d (ML-KEM ct) bytes"
                         % (X25519_PT_LEN, MLKEM_CT_LEN))
    ok.send_large_message2(msg=Message.OKDECRYPT, slot_id=slot, payload=list(bytes(data)))
    return read_exact(ok, SS_LEN, timeout_ms or _op_timeout())


def sign(ok, slot, component, digest, timeout_ms=None):
    """Composite sign. component = HALF_ECC (Ed25519) or HALF_PQC (ML-DSA-65).
    Payload is [selector] + digest; returns the 64-byte or 3309-byte signature
    as BYTES.

    Raises the three-button confirmation on the device."""
    if component not in (HALF_ECC, HALF_PQC):
        raise ValueError("component must be HALF_ECC(0) or HALF_PQC(1)")
    payload = bytes([component]) + bytes(digest)
    ok.send_large_message2(msg=Message.OKSIGN, slot_id=slot, payload=list(payload))
    want = ED25519_SIG_LEN if component == HALF_ECC else MLDSA_SIG_LEN
    return read_exact(ok, want, timeout_ms or _op_timeout())


def _op_timeout():
    # Dominated by the HUMAN, not the device: every composite operation waits on
    # a three-button confirmation, so this budget is sized for a person reading
    # three digits off the display and pressing them. The device-side work
    # either side of that - ML-DSA keygen-from-seed then sign, or ML-KEM keygen
    # then decapsulate - is small by comparison.
    return 30000
