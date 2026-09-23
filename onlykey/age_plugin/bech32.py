"""Bech32 encoding for age recipients/identities.

Simplified implementation for age1onlykey1... / AGE-PLUGIN-ONLYKEY-1...
format - deliberately has no length cap (unlike the standard `bech32` PyPI
package, which enforces BIP-173's 90-character limit), since a 1216-byte
X-Wing recipient encodes to something far longer than that.

Extracted from cli.py (where this originated, used correctly there for the
slot-based recipient/identity encoding) into its own module so
derived_xwing.py can use the same encoder for derived identities without a
circular import between the two.
"""

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
    data = [BECH32_CHARSET.find(x) for x in bech[pos + 1:]]
    if -1 in data:
        return None, None
    if not _bech32_verify_checksum(hrp, data):
        return None, None
    decoded = _convertbits(data[:-6], 5, 8, False)
    if decoded is None:
        return None, None
    return hrp, bytes(decoded)
