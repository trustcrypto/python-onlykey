"""pgp_bridge.py — parse OpenPGP private keys via a Node / OpenPGP.js bridge.

Replaces PGPy. OpenPGP.js understands both classic keys (RSA / ECC) **and** the
IETF OpenPGP-PQC composite keys (ML-DSA-65 + ML-KEM-768) that PGPy cannot read,
and it is the same engine the web app uses — so parsing behaviour matches.

Requires **Node.js** on PATH. The bundle lives in ``onlykey/openpgp_bridge/``.

parse_armored() returns one of:
  {'type': 'pqc-composite', 'blob': <320-hex-char = 160 bytes>}
  {'type': 'rsa', 'keys': [{'name','kind':'rsa','p','q'(hex)}, ...]}
  {'type': 'ecc', 'keys': [{'name','kind':'ecc','s'(hex),'curve'(int)}, ...]}
"""

import binascii
import json
import os
import shutil
import subprocess
import tempfile

_BRIDGE_DIR = os.path.join(os.path.dirname(__file__), 'openpgp_bridge')
_BRIDGE_JS = os.path.join(_BRIDGE_DIR, 'bridge.js')


def _node():
    node = shutil.which('node')
    if not node:
        raise RuntimeError(
            'Node.js is required to parse PGP keys (OpenPGP.js bridge). '
            'Install Node.js and ensure `node` is on PATH.')
    return node


def parse_key_file(path, passphrase=None):
    """Parse an armored PGP private key file; return the bridge dict."""
    args = [_node(), _BRIDGE_JS, 'parse', path]
    if passphrase:
        args.append(passphrase)
    proc = subprocess.run(args, capture_output=True, text=True, timeout=120)
    if proc.returncode != 0:
        raise RuntimeError('PGP parse failed: ' + (proc.stderr.strip() or proc.stdout.strip()))
    return json.loads(proc.stdout)


def parse_armored(armored, passphrase=None):
    """Parse an armored PGP private key given as a string."""
    with tempfile.NamedTemporaryFile('w', suffix='.asc', delete=False) as f:
        f.write(armored)
        tmp = f.name
    try:
        return parse_key_file(tmp, passphrase)
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def composite_blob(armored=None, path=None, passphrase=None):
    """Return the 160-byte composite PQC blob (bytes) for loadpqc / load_composite_key."""
    d = parse_key_file(path, passphrase) if path else parse_armored(armored, passphrase)
    if d.get('type') != 'pqc-composite':
        raise RuntimeError('not a composite PQC PGP key (got %r)' % d.get('type'))
    blob = binascii.unhexlify(d['blob'])
    if len(blob) != 160:
        raise RuntimeError('composite blob must be 160 bytes, got %d' % len(blob))
    return blob
