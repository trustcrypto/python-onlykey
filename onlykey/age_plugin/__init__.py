"""age-plugin-onlykey: age encryption plugin for OnlyKey hardware tokens.

Supports ML-KEM-768 (FIPS 203) and X-Wing hybrid KEM
(draft-connolly-cfrg-xwing-kem-09) for post-quantum encryption.

The plugin produces native ``mlkem768x25519`` stanzas using OnlyKey-managed
X-Wing keys. This is narrower and more precise than claiming blanket
compatibility with every age recipient or identity flow.
"""

__version__ = "0.1.0"
PLUGIN_NAME = "onlykey"

# OnlyKey HID opcodes (values match onlykey.client.Message)
OKGETPUBKEY = 236   # Message.OKGETPUBKEY
OKDECRYPT = 240     # Message.OKDECRYPT
OKSETPRIV = 239     # Message.OKSETPRIV — also generates an on-device key when
                    # the key body is all 0xFF (firmware okcore.cpp set_private
                    # -> okcrypto_generate_random_key)

# ECC key slots that can hold the 32-byte post-quantum seed.
#
# A ML-KEM/X-Wing key is just a 32-byte seed stored in an ordinary ECC key
# slot, and the algorithm is chosen by the key-type byte (buffer[6]) below —
# not by the slot number. The slot is therefore caller-selectable, but only
# across the USER key slots: firmware exposes 101-116 (16 slots) for user keys.
# Slots 117-132 are RESERVED (e.g. 128 web-derivation, 129/130 HMAC, 131
# backup, 132 derivation) and must never be used for PQ keys — writing there
# would clobber internal device keys. Firmware getpubkey/decaps enforce this
# with a `< 117` gate (okcrypto.cpp); the host mirrors it here.
ECC_SLOT_MIN = 101
ECC_SLOT_MAX = 116            # 16 user ECC key slots: 101-116 (117-132 reserved)
DEFAULT_XWING_SLOT = 101
DEFAULT_MLKEM_SLOT = 102


def validate_ecc_slot(slot):
    """Raise ValueError unless slot is a user ECC key slot (101-116).

    117-132 are reserved by firmware and are intentionally rejected.
    """
    if not (ECC_SLOT_MIN <= int(slot) <= ECC_SLOT_MAX):
        raise ValueError(
            f"PQ key slot must be a user ECC slot {ECC_SLOT_MIN}-{ECC_SLOT_MAX} "
            f"(117-132 are reserved), got {slot}"
        )
    return int(slot)

# Firmware key-type identifiers (okcore.h: KEYTYPE_MLKEM768 / KEYTYPE_XWING).
# Sent in the low nibble of buffer[6] so the device routes the operation.
KEYTYPE_MLKEM768 = 5
KEYTYPE_XWING = 6

# An all-0xFF key body sent with OKSETPRIV tells the firmware to generate the
# key on-device (gen_key trigger in okcore.cpp).
GENERATE_ON_DEVICE = b"\xff" * 8
