#!/usr/bin/env python3
"""age-plugin-onlykey: age encryption plugin for OnlyKey hardware tokens.

Usage:
  age-plugin-onlykey                     Interactive key management
  age-plugin-onlykey --generate          Generate X-Wing keypair on OnlyKey
  age-plugin-onlykey --identity          Print identity for use with age -i
  age-plugin-onlykey --recipient         Print recipient for use with age -r
  age-plugin-onlykey --age-plugin=STATE  Run plugin state machine (called by age)

Encryption:
  age -r age1onlykey1<pubkey> -e secret.txt > secret.age

Decryption:
  age -d -i onlykey-identity.txt secret.age > secret.txt
"""

import sys
import os
import base64
import hashlib

from onlykey.age_plugin import __version__, PLUGIN_NAME, SLOT_XWING
from onlykey.age_plugin.protocol import (
    Stanza, b64encode_no_pad, b64decode_no_pad,
    run_identity_v1, run_recipient_v1,
)


# Bech32 encoding for age recipients/identities
# Simplified implementation for age1onlykey1... format

BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _bech32_polymod(values):
    """Internal function for Bech32 checksum."""
    GEN = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _bech32_create_checksum(hrp, data):
    values = _bech32_hrp_expand(hrp) + data
    polymod = _bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def _bech32_verify_checksum(hrp, data):
    return _bech32_polymod(_bech32_hrp_expand(hrp) + data) == 1


def _convertbits(data, frombits, tobits, pad=True):
    """General power-of-2 base conversion."""
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


def bech32_encode(hrp: str, data: bytes) -> str:
    """Encode bytes as Bech32."""
    values = _convertbits(list(data), 8, 5)
    checksum = _bech32_create_checksum(hrp, values)
    return hrp + "1" + "".join(BECH32_CHARSET[d] for d in values + checksum)


def bech32_decode(bech: str):
    """Decode Bech32 string to (hrp, data_bytes)."""
    if any(ord(x) < 33 or ord(x) > 126 for x in bech):
        return None, None
    bech = bech.lower()
    pos = bech.rfind("1")
    if pos < 1 or pos + 7 > len(bech):
        return None, None
    hrp = bech[:pos]
    data = [BECH32_CHARSET.find(x) for x in bech[pos + 1 :]]
    if -1 in data:
        return None, None
    if not _bech32_verify_checksum(hrp, data):
        return None, None
    decoded = _convertbits(data[:-6], 5, 8, False)
    if decoded is None:
        return None, None
    return hrp, bytes(decoded)


# HRP for OnlyKey age recipients and identities
RECIPIENT_HRP = "age1onlykey"
IDENTITY_HRP = "age-plugin-onlykey-"  # uppercase AGE-PLUGIN-ONLYKEY- in file

IDENTITY_VERSION = 1
IDENTITY_FINGERPRINT_LEN = 8
XWING_RECIPIENT_LEN = 1216
XWING_STANZA_ENC_LEN = 1120
FILE_KEY_LEN = 32


def encode_recipient(pubkey: bytes) -> str:
    """Encode X-Wing public key as age recipient string."""
    return bech32_encode(RECIPIENT_HRP, pubkey)


def decode_recipient(recipient: str) -> bytes:
    """Decode age recipient string to public key bytes."""
    hrp, data = bech32_decode(recipient.lower())
    if hrp != RECIPIENT_HRP or data is None:
        raise ValueError(f"Invalid OnlyKey recipient: {recipient}")
    return data


def recipient_fingerprint(pubkey: bytes) -> bytes:
    """Return a short fingerprint for identity binding."""
    return hashlib.sha256(pubkey).digest()[:IDENTITY_FINGERPRINT_LEN]


def encode_identity(slot: int = SLOT_XWING) -> str:
    """Encode an identity string. Contains just the slot number."""
    # Identity data: just the slot byte
    data = bytes([slot])
    return bech32_encode(IDENTITY_HRP, data).upper().replace(
        IDENTITY_HRP.upper() + "1",
        "AGE-PLUGIN-ONLYKEY-1"
    )


def decode_identity(identity: str) -> dict:
    """Decode identity string.

    Returns a mapping with ``slot``, ``fingerprint``, and ``legacy`` keys.
    Legacy one-byte identities are supported so older files continue to work.
    """
    hrp, data = bech32_decode(identity.lower())
    if hrp != IDENTITY_HRP or data is None or len(data) < 1:
        raise ValueError(f"Invalid OnlyKey identity: {identity}")

    if len(data) == 1:
        return {
            "slot": data[0],
            "fingerprint": None,
            "legacy": True,
        }

    if len(data) != 2 + IDENTITY_FINGERPRINT_LEN:
        raise ValueError(
            f"Invalid OnlyKey identity payload length: {len(data)}"
        )

    version = data[0]
    if version != IDENTITY_VERSION:
        raise ValueError(f"Unsupported OnlyKey identity version: {version}")

    return {
        "slot": data[1],
        "fingerprint": data[2:],
        "legacy": False,
    }



def cmd_generate():
    """Generate X-Wing keypair on OnlyKey and print recipient/identity."""
    from onlykey.age_plugin.onlykey_hid import OnlyKeyPQ

    print("Generating X-Wing keypair on OnlyKey...", file=sys.stderr)
    dev = OnlyKeyPQ()
    pk = dev.xwing_keygen()

    recipient = encode_recipient(pk)
    identity = encode_identity(SLOT_XWING)

    print("# X-Wing public key (produces native age mlkem768x25519 stanzas)", file=sys.stderr)
    print(f"# Recipient: {recipient}", file=sys.stderr)
    print(file=sys.stderr)

    # Print identity to stdout (for saving to file)
    print(f"# created: {__import__('datetime').datetime.now().isoformat()}")
    print(f"# recipient: {recipient}")
    print(identity)


def cmd_recipient():
    """Print the current X-Wing public key as an age recipient."""
    from onlykey.age_plugin.onlykey_hid import OnlyKeyPQ

    dev = OnlyKeyPQ()
    pk = dev.xwing_getpubkey()
    print(encode_recipient(pk))


def cmd_identity():
    """Print an identity file for use with age -i."""
    identity = encode_identity(SLOT_XWING)
    print(f"# age-plugin-onlykey identity (X-Wing slot {SLOT_XWING})")
    print(identity)


def _parse_onlykey_identities(identities):
    parsed = []
    for identity in identities:
        try:
            parsed.append(decode_identity(identity))
        except ValueError:
            continue
    return parsed


def unwrap_callback(identities, stanzas_per_file):
    """Plugin identity-v1 callback: unwrap file keys using OnlyKey."""
    from onlykey.age_plugin.onlykey_hid import OnlyKeyPQ
    from onlykey.age_plugin.xwing import open_file_key

    results = []
    parsed_identities = _parse_onlykey_identities(identities)
    if not parsed_identities:
        print("No valid OnlyKey identity supplied.", file=sys.stderr)
        return results

    dev = OnlyKeyPQ()
    device_pubkey = dev.xwing_getpubkey()
    if len(device_pubkey) != XWING_RECIPIENT_LEN:
        raise ValueError(
            f"OnlyKey returned an unexpected X-Wing public key length: {len(device_pubkey)}"
        )

    device_fingerprint = recipient_fingerprint(device_pubkey)
    matching_identity = None
    for identity in parsed_identities:
        if identity["slot"] != SLOT_XWING:
            continue
        if identity["fingerprint"] is None or identity["fingerprint"] == device_fingerprint:
            matching_identity = identity
            break

    if matching_identity is None:
        print(
            "OnlyKey identity does not match the connected device's X-Wing public key.",
            file=sys.stderr,
        )
        return results

    for file_idx, stanzas in stanzas_per_file.items():
        for stanza in stanzas:
            # We only handle mlkem768x25519 stanzas
            if stanza.tag != "mlkem768x25519":
                continue

            if len(stanza.args) != 1:
                raise ValueError(
                    f"Malformed mlkem768x25519 stanza: expected 1 arg, got {len(stanza.args)}"
                )

            # Parse the ciphertext from the stanza argument
            try:
                enc = b64decode_no_pad(stanza.args[0])
            except Exception as exc:
                raise ValueError(
                    "Malformed mlkem768x25519 stanza: invalid base64 ciphertext"
                ) from exc

            if len(enc) != XWING_STANZA_ENC_LEN:
                raise ValueError(
                    f"Malformed mlkem768x25519 stanza: ciphertext must be {XWING_STANZA_ENC_LEN} bytes, got {len(enc)}"
                )

            # Body must be exactly 32 bytes
            if len(stanza.body) != FILE_KEY_LEN:
                raise ValueError(
                    f"Malformed mlkem768x25519 stanza body: expected {FILE_KEY_LEN} bytes, got {len(stanza.body)}"
                )


            # Send ciphertext to OnlyKey for decapsulation
            ss = dev.xwing_decaps(enc)

            # Use shared secret to decrypt the file key via HPKE
            try:
                file_key = open_file_key(ss, enc, stanza.body)
                results.append((file_idx, file_key))
                break  # Found a matching stanza for this file
            except Exception as e:
                print(f"HPKE unwrap failed: {e}", file=sys.stderr)
                continue

    return results


def wrap_callback(recipients, identities, file_keys):
    """Plugin recipient-v1 callback: wrap file keys for OnlyKey recipients."""
    from onlykey.age_plugin.onlykey_hid import OnlyKeyPQ
    from onlykey.age_plugin.xwing import xwing_encaps_host, seal_file_key

    results = []
    dev = None

    for recipient in recipients:
        try:
            pk = decode_recipient(recipient)
        except ValueError:
            continue

        if len(pk) != 1216:
            continue

        for file_idx, file_key in file_keys:
            # X-Wing encapsulate (host-side)
            ss, enc = xwing_encaps_host(pk)

            # HPKE seal the file key
            body = seal_file_key(ss, enc, file_key)

            stanza = Stanza(
                "mlkem768x25519",
                [b64encode_no_pad(enc)],
                body,
            )
            results.append((file_idx, [stanza]))

    return results


def main():
    """Main entry point."""
    args = sys.argv[1:]

    # Plugin state machine mode (called by age)
    for arg in args:
        if arg.startswith("--age-plugin="):
            state_machine = arg.split("=", 1)[1]
            if state_machine == "identity-v1":
                run_identity_v1(unwrap_callback)
                return
            elif state_machine == "recipient-v1":
                run_recipient_v1(wrap_callback)
                return
            else:
                print(f"Unknown state machine: {state_machine}", file=sys.stderr)
                sys.exit(1)

    # Direct invocation modes
    if "--generate" in args or "-g" in args:
        cmd_generate()
    elif "--recipient" in args or "-r" in args:
        cmd_recipient()
    elif "--identity" in args or "-i" in args:
        cmd_identity()
    elif "--version" in args or "-v" in args:
        print(f"age-plugin-onlykey {__version__}")
    elif "--help" in args or "-h" in args:
        print(__doc__)
    else:
        # Interactive mode
        print(f"age-plugin-onlykey v{__version__}")
        print(f"Post-quantum encryption for OnlyKey hardware tokens")
        print()
        print("Commands:")
        print("  --generate    Generate X-Wing keypair on OnlyKey")
        print("  --recipient   Print recipient (public key) for encryption")
        print("  --identity    Print identity file for decryption")
        print("  --help        Show full help")
        print()
        print("Quick start:")
        print("  age-plugin-onlykey --generate > onlykey-identity.txt")
        print("  age -r $(age-plugin-onlykey --recipient) -e secret.txt > secret.age")
        print("  age -d -i onlykey-identity.txt secret.age > secret.txt")


if __name__ == "__main__":
    main()
