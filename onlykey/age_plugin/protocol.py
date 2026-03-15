"""age plugin protocol: stdin/stdout state machine per C2SP age-plugin.md.

Implements both recipient-v1 (encrypt) and identity-v1 (decrypt) state machines.
"""

import sys
import base64
import io


def b64encode_no_pad(data: bytes) -> str:
    """Base64 encode without padding (age uses unpadded base64)."""
    return base64.b64encode(data).rstrip(b"=").decode("ascii")


def b64decode_no_pad(s: str) -> bytes:
    """Base64 decode with or without padding."""
    # Add padding back
    pad = 4 - (len(s) % 4)
    if pad != 4:
        s += "=" * pad
    return base64.b64decode(s)


class Stanza:
    """An age stanza: tag + args + body."""

    def __init__(self, tag: str, args: list[str] = None, body: bytes = b""):
        self.tag = tag
        self.args = args or []
        self.body = body

    def encode(self) -> str:
        """Encode stanza for writing to stdout."""
        parts = ["-> " + self.tag]
        parts.extend(self.args)
        line = " ".join(parts) + "\n"

        if self.body:
            encoded = b64encode_no_pad(self.body)
            # Wrap at 64 characters
            lines = [encoded[i : i + 64] for i in range(0, len(encoded), 64)]
            # Final line must be < 64 chars (or empty for exact multiple)
            if lines and len(lines[-1]) == 64:
                lines.append("")
            line += "\n".join(lines) + "\n"
        else:
            line += "\n"
        return line


def read_stanza(stream=None) -> Stanza | None:
    """Read a single stanza from stdin."""
    if stream is None:
        stream = sys.stdin

    # Read the command line starting with ->
    while True:
        line = stream.readline()
        if not line:
            return None
        line = line.rstrip("\n").rstrip("\r")
        if line.startswith("-> "):
            break

    parts = line[3:].split(" ")
    tag = parts[0]
    args = parts[1:]

    # Read body lines (base64, 64 chars each, final line < 64 or empty)
    body_parts = []
    while True:
        line = stream.readline()
        if not line:
            break
        line = line.rstrip("\n").rstrip("\r")
        if len(line) == 64:
            body_parts.append(line)
        else:
            if line:
                body_parts.append(line)
            break

    body = b""
    if body_parts:
        body = b64decode_no_pad("".join(body_parts))

    return Stanza(tag, args, body)


def write_stanza(stanza: Stanza, stream=None):
    """Write a stanza to stdout."""
    if stream is None:
        stream = sys.stdout
    stream.write(stanza.encode())
    stream.flush()


def write_command(tag: str, args: list[str] = None, body: bytes = b"", stream=None):
    """Convenience: write a command stanza."""
    write_stanza(Stanza(tag, args or [], body), stream)


def run_identity_v1(unwrap_callback):
    """Run the identity-v1 state machine for decryption.

    unwrap_callback(identities, stanzas_per_file) -> list of (file_index, file_key) or errors

    The callback receives:
      - identities: list of identity strings (bech32)
      - stanzas_per_file: dict mapping file_index -> list of Stanza

    It should return a list of (file_index, file_key_bytes) tuples for
    successful unwraps, or raise an error.
    """
    identities = []
    stanzas_per_file = {}  # file_index -> [Stanza]

    # Phase 1: Read commands from client
    while True:
        stanza = read_stanza()
        if stanza is None:
            sys.exit(1)

        if stanza.tag == "add-identity":
            if stanza.args:
                identities.append(stanza.args[0])
        elif stanza.tag == "recipient-stanza":
            if len(stanza.args) >= 2:
                file_idx = int(stanza.args[0])
                # Reconstruct the recipient stanza
                rs = Stanza(
                    stanza.args[1],
                    stanza.args[2:],
                    stanza.body,
                )
                stanzas_per_file.setdefault(file_idx, []).append(rs)
        elif stanza.tag == "done":
            break
        else:
            # Ignore unknown commands (grease)
            pass

    # Phase 2: Process and respond
    try:
        results = unwrap_callback(identities, stanzas_per_file)

        for file_idx, file_key in results:
            write_command("file-key", [str(file_idx)], file_key)

    except Exception as e:
        # Report error
        write_command("error", [str(e)])

    # Signal done
    write_command("done")


def run_recipient_v1(wrap_callback):
    """Run the recipient-v1 state machine for encryption.

    wrap_callback(recipients, identities, file_keys) -> list of (file_index, [Stanza])

    The callback receives:
      - recipients: list of recipient strings (bech32)
      - identities: list of identity strings (bech32)
      - file_keys: list of (file_index, file_key_bytes) tuples

    It should return a list of (file_index, [recipient_stanza]) tuples.
    """
    recipients = []
    identities = []
    file_keys = []
    supports_labels = False

    # Phase 1: Read commands
    file_idx = 0
    while True:
        stanza = read_stanza()
        if stanza is None:
            sys.exit(1)

        if stanza.tag == "add-recipient":
            if stanza.args:
                recipients.append(stanza.args[0])
        elif stanza.tag == "add-identity":
            if stanza.args:
                identities.append(stanza.args[0])
        elif stanza.tag == "wrap-file-key":
            file_keys.append((file_idx, stanza.body))
            file_idx += 1
        elif stanza.tag == "extension-labels":
            supports_labels = True
        elif stanza.tag == "done":
            break

    # Phase 2: Wrap and respond
    try:
        results = wrap_callback(recipients, identities, file_keys)

        for fidx, stanzas in results:
            for s in stanzas:
                write_command(
                    "recipient-stanza",
                    [str(fidx), s.tag] + s.args,
                    s.body,
                )

        # If we support labels and the client asked, send labels
        if supports_labels:
            # mlkem768x25519 stanzas have the "postquantum" label
            write_command("labels", ["postquantum"])

    except Exception as e:
        write_command("error", [str(e)])

    write_command("done")
