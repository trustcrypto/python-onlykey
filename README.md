# python-onlykey

Python client for interacting with the OnlyKey. Bundled with a CLI for configuring and helpers for loading secrets.

**Still in early development.**

## Installation

The package is not published on PyPI yet.

You can install it via pip:

```
$ pip install git+git://github.com/trustcrypto/python-onlykey.git
```

```
$ git clone https://github.com/trustcrypto/python-onlykey.git
$ cd python-onlykey
$ python setup.py install
```

## QuickStart

### CLI

The CLI is bundled with the package, it should be present globally after the install.

```
$ onlykey-cli
OnlyKey CLI v0
Press the right arrow to insert the suggestion.
Press Control-C to retry. Control-D to exit.

OnlyKey> getlabels

Slot 1a: <empty>
Slot 1b: <empty>

Slot 2a: <empty>
Slot 2b: <empty>

Slot 3a: <empty>
Slot 3b: <empty>

Slot 4a: <empty>
Slot 4b: <empty>

Slot 5a: <empty>
Slot 5b: <empty>

Slot 6a: <empty>
Slot 6b: <empty>

OnlyKey> setslot 1 label ok

Successfully set Label

OnlyKey> setslot 1 password
Type Control-T to toggle password visible.
Password: ***

Successfully set Password

OnlyKey> getlabels

Slot 1a: ok
Slot 1b: <empty>

Slot 2a: <empty>
Slot 2b: <empty>

Slot 3a: <empty>
Slot 3b: <empty>

Slot 4a: <empty>
Slot 4b: <empty>

Slot 5a: <empty>
Slot 5b: <empty>

Slot 6a: <empty>
Slot 6b: <empty>

OnlyKey>

Bye!
```

### Creating/Loading SSH key

Create a new ed25519 private key and load it into the OnlyKey:

```
$ onlykey-utils ssh new
$ onlykey-utils ssh load
```

See [onlykey-agent](https://github.com/trustcrypto/onlykey-agent) for more informations.

### Python client

```python
from onlykey import OnlyKey, Message

# Automatically connect
ok = OnlyKey()

ok.sendmessage(msg=Message.OKGETLABELS)
print ok.read_string()
```
