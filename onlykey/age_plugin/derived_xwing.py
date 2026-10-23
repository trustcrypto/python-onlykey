"""Derived (label-based) X-Wing identity encoding for age-plugin-onlykey.

The OnlyKey derives the X-Wing keypair from (web-and-agent derivation key,
label) - no origin in it (firmware seed/v3) - and keeps both halves on the
device. Same derivation => the SAME X-Wing key on the CLI and on every web
origin, so a file encrypted in one decrypts in the other on the same OnlyKey.

kyber-py's ML-KEM-768 is byte-compatible with the web app's @noble/post-quantum
(verified: same pk from same seed, cross-decapsulation matches).

Wire contract with the firmware HID derive branch (RESERVED_KEY_WEB_DERIVATION,
keytype X-Wing), matching the FIDO2 branch:
  OKGETPUBKEY with tag(32)          -> [ pk_M(1184) | pk_X(32) ] = the recipient
  OKDECRYPT with [tag(32)|ct(1120)] -> [ ss(32) ] = the X-Wing shared secret

SPLIT CUSTODY IS GONE. The device used to return a 32-byte ML-KEM seed and let
this module expand it, run ML-KEM decapsulation and combine the halves. The seed
is private key material - it yields sk_M - so a request for a public key was
answered with a private one, and the ML-KEM half of a hardware key really lived
in this process. mlkem_keypair_from_seed(), build_recipient(),
split_decapsulate() and ct_x_of() went with it; what remains here is
host/sender-side math on public values plus the identity encoding.
"""

import hashlib

from kyber_py.ml_kem import ML_KEM_768

# draft-connolly-cfrg-xwing-kem-09 combiner label "\.//^\"
XWING_LABEL = bytes([0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c])

MLKEM_PK = 1184
MLKEM_CT = 1088
XWING_PK = 1216
XWING_CT = 1120
SEED = 32


# ---- derived age identity encoding (label-based, no slot) ----------------
# Distinguishes a derived identity from a slot identity so age-plugin-onlykey
# can support BOTH models (like SSH/GPG). A derived identity carries the label;
# the key is reproduced on demand from (OnlyKey web-and-agent derivation key, label).
#
# Real bech32 (cli.py's bech32_encode/decode, extracted to bech32.py so both
# modules can share it without a circular import), matching the slot-based
# encode_identity()'s scheme - NOT the naive base32-with-no-checksum
# concatenation this used to be. That produced strings like
# "AGE-PLUGIN-ONLYKEY-DERIVED-<base32>" with no "1" bech32 separator and no
# checksum, which `age` itself rejects outright before ever handing off to
# the plugin ("invalid identity encoding: separator '1' at invalid
# position") - observed running an actual `age -d -i <file>` against one.
#
# Second, deeper issue found the same way, fixed here too: the HRP can't be
# a distinct "age-plugin-onlykey-derived-" string either, even bech32-valid.
# `age` picks which plugin *binary* to run from the "AGE-PLUGIN-<NAME>-"
# prefix text itself (name -> `age-plugin-<name>`), so a
# "AGE-PLUGIN-ONLYKEY-DERIVED-1..." identity made `age` look for a
# nonexistent `age-plugin-onlykey-derived` executable instead of invoking
# the real, installed `age-plugin-onlykey` - confirmed live
# ("couldn't start plugin: exec: ... not found in $PATH"). The HRP has to
# be *exactly* cli.py's IDENTITY_HRP (kept as a literal here, not imported,
# to avoid a cross-module dependency for one constant - the two must match,
# noted in both places). Slot vs. derived identities are instead
# distinguished by a marker byte in the decoded payload: cli.py's
# decode_identity() only ever produces `data[0]` in {a valid slot 1-132} or
# {IDENTITY_VERSION==1}, so 0xFF as data[0] is unambiguous and safe - the
# slot decoder raises ValueError on it either way (wrong length or
# unrecognized version), which callers already catch and skip.
from onlykey.age_plugin.bech32 import bech32_encode, bech32_decode

_IDENTITY_HRP = "age-plugin-onlykey-"  # MUST match cli.py's IDENTITY_HRP
_DERIVED_MARKER = 0xFF


def encode_identity(label):
    """Encode a derived identity string for a label (used with `age -i`)."""
    if not isinstance(label, str) or not label:
        raise ValueError("derived identity needs a non-empty label")
    payload = bytes([_DERIVED_MARKER]) + label.encode("utf-8")
    return bech32_encode(_IDENTITY_HRP, payload).upper()


def decode_identity(s):
    """Decode a derived identity string -> {'derived': True, 'label': str},
    or None if `s` is not a derived identity (caller falls back to slot decode)."""
    hrp, data = bech32_decode(str(s).strip().lower())
    if hrp != _IDENTITY_HRP or not data or data[0] != _DERIVED_MARKER:
        return None
    return {"derived": True, "label": data[1:].decode("utf-8")}
