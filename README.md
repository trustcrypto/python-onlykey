# python-onlykey

Python client for interacting with the OnlyKey. Bundled with a CLI for configuring and helpers for loading secrets.

**Still in early development.**

## QuickStart

```python
from onlykey import OnlyKey, Message

# Automatically connect
ok = OnlyKey()

ok.sendmessage(msg=Message.OKGETLABELS)
print ok.read_string()
```
