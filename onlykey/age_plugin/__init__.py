"""age-plugin-onlykey: age encryption plugin for OnlyKey hardware tokens.

Supports ML-KEM-768 (FIPS 203) and X-Wing hybrid KEM
(draft-connolly-cfrg-xwing-kem-09) for post-quantum encryption,
compatible with age v1.3.0's mlkem768x25519 recipient type.
"""

__version__ = "0.1.0"
PLUGIN_NAME = "onlykey"

# OnlyKey HID message types (from onlykey.client.Message)
OKGETPUBKEY = 236
OKDECRYPT = 240
OKGENKEY = 230

# OnlyKey reserved key slots for post-quantum
SLOT_MLKEM = 133
SLOT_XWING = 134
