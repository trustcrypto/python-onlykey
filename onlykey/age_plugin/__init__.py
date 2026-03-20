"""age-plugin-onlykey: age encryption plugin for OnlyKey hardware tokens.

Supports ML-KEM-768 (FIPS 203) and X-Wing hybrid KEM
(draft-connolly-cfrg-xwing-kem-09) for post-quantum encryption.

The plugin produces native ``mlkem768x25519`` stanzas using OnlyKey-managed
X-Wing keys. This is narrower and more precise than claiming blanket
compatibility with every age recipient or identity flow.
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
