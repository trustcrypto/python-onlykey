# python-onlykey

Python client for interacting with the OnlyKey. Bundled with a CLI for configuring and helpers for loading secrets.

**Still in early development.**

## QuickStart

```python
import onlykey

# Automatically connect
ok = onlykey.OnlyKey()

if ok.initialized():
    ok.sendmessage(msg=onlykey.OKGETLABELS)

    print ok.read_string()
```
