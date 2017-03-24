# python-onlykey

Python client for interacting with the OnlyKey. Bundled with a CLI for configuring and helpers for loading secrets.

**Still in early development.**

<!---## Ubuntu Install Dependencies

Tested on Ubuntu 16.04
Requires git, setuptools, python-dev, python-pip, libusb-1.0-0-dev, libudev-dev
```
$ sudo apt-get install git python-setuptools python-dev libusb-1.0-0-dev libudev-dev python-pip
```

Additionally, in order for non-root users to be able to communicate with OnlyKey a udev rule must be created as described [here](https://www.pjrc.com/teensy/td_download.html).--->

<!---## Mac OS Install Dependencies

Tested on El Capitan
```
$brew install pkg-config libffi
 export PKG_CONFIG_PATH=/usr/local/Cellar/libffi/3.0.13/lib/pkgconfig/
  pip install bcrypt 
sudo pip uninstall crypto
  sudo pip uninstall pycrypto
  sudo pip install pycrypto
```
--->

## Run without installation

Pre-compiled packaged apps have been provided here:

[OnlyKey CLI]

[OnlyKey PGP Message Tool]

Once the file is downloaded it can be run on Mac OS by right clicking and agreeing to open the file you downloaded from the Internet.

These have been tested on Mac OS (El Capitan), we are still working on getting packaged apps that will work on other platforms such as Windows.

## Installation

```
$ git clone https://github.com/trustcrypto/python-onlykey.git --recursive
$ cd python-onlykey
$ sudo python setup.py install
$ cd PGPy
$ sudo python setup.py install
$ cd ..
```

## QuickStart

### Init

You can set your pins using the special `onlykey-init` command.

```
$ onlykey-init
OnlyKey is ready, enter your PIN
Press the Enter key once you are done
Successful PIN entry
OnlyKey is ready, re-enter your PIN to confirm
Press the Enter key once you are done
Successfully set PIN
[...]
```


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

OnlyKey> setslot 1 url accounts.google.com

Successfully set URL

OnlyKey> setslot 1 add_char1 2

Successfully set Character1

OnlyKey> setslot 1 delay1 2

Successfully set Delay1

OnlyKey> setslot 1 username onlykey.1234

Successfully set Username

OnlyKey> setslot 1 add_char2 2

Successfully set Character2

OnlyKey> setslot 1 delay2 2

Successfully set Delay2

OnlyKey> setslot 1 password

Type Control-T to toggle password visible.
Password: *********
Successfully set Password

OnlyKey> setslot 1 add_char3 2

Successfully set Character3

OnlyKey> setslot 1 delay3 2

Successfully set Delay3

OnlyKey> setslot 1 type g

Successfully set 2FA Type

OnlyKey> setslot 1 totpkey

Type Control-T to toggle password visible.
Password: ********************************
Successfully set TOTP Key

OnlyKey> setslot 1 add_char4 2

Successfully set Character4

OnlyKey> 

Bye!
```

### Creating/Loading SSH key (ED25519 only)

Create a new ed25519 private key and load it into the OnlyKey:

```
$ python tests/ssh_auth_ed25519.py
```

See [onlykey-agent](https://github.com/trustcrypto/onlykey-agent) for more information on SSH authentication.

The latest OnlyKey Chrome App can also be used to load ECC keys. See [OnlyKey-Chrome-App](https://github.com/trustcrypto/OnlyKey-Chrome-App) for more informations.


### Creating/Loading PGP key 

Create a new RSA 1024 bit private key and load it into the OnlyKey:

```
$ python tests/rsa_decrypt_1024.py
```

Create a new RSA 2048 bit private key and load it into the OnlyKey:

```
$ python tests/rsa_decrypt_2048.py
```

Create a new RSA 3072 bit private key and load it into the OnlyKey:

```
$ python tests/rsa_decrypt_3072.py
```

Create a new RSA 4096 bit private key and load it into the OnlyKey:

```
$ python tests/rsa_decrypt_4096.py
```

The latest OnlyKey Chrome App can also be used to load RSA keys. See [OnlyKey-Chrome-App](https://github.com/trustcrypto/OnlyKey-Chrome-App) for more informations.

### Testing PGP decryption

If you already have a key loaded and you want to test decryption:

```
$ python tests/rsa_decrypt_testkey.py
```

You will be prompted to 

`Enter RSA slot number to use for decryption (1 - 4)`

Select the slot where your key is loaded, this will be used to do PKCS1 v 15 decyption of an encrypted message 


### Decrypt PGP email messages using OnlyKey

If you using a previously set RSA private key you can decrypt OpenPGP/GPG encrypted email messages:

```
$ python tests/decrypt_PGP_message.py
```

You will be prompted to 

`Paste OpenPGP Message, press Ctrl+D or Ctrl+Z(Windows only) when finished`

```
-----BEGIN PGP MESSAGE-----
Version: Mailvelope v1.7.1
Comment: https://www.mailvelope.com

wcFMA322sr0GLHtKARAAqx//02T7y0MQq4+qbWV34AQxRUvpSQJwMT7li4LR
nOK3m/QySqjqSunuGKV4H+4qHJ1sGOLlBicZrINQsqQmlvYQEvv3dkFD9kk1
Bg7UyZbhYTGR9OivuHr2Ft3YWjgYBe1t4frmzGZFe+TfBH0EdSWDNz7ihTRC
/JjhK8bQR6EUS6nbZMn3FSJ/NlBUxoKT9lfY4iC1/4gqvPs1hDmngvAPSEJQ
6ZRIx6aDlt061Q4w4B++Y2No+3fKfet3Sx+UTZbE7jwD0sdySmpFbp4p42/M
ocJuZFXz/bZOUy0wWVLcS50ThrH7kuN25z+a1JSFrZWbC9e321DqkmuIGe0O
1LQbeVb0B27JiTjalfk1usriy0EoXdEnHDUwu+/oX5fDc4RH9hl/ul9Ig5q1
xc3XJ0DjUNTtjz7PYGB1NWrJbwMfT3cottaO3LvulkbVLtvfEMrI/rc1r83B
rRYQNzfmdDoNTQhT5VLE9GdLWD6ZpyE/FHe769n2qKtob7pwmtoo62yrrDV3
aY/xHL1NiVuis51ebdGU/wA3mANnp8beyLhdmgwNbiX6dJDcUcRYnb9L0kSx
P7M8IbeUOxMktC9ZRSzJmUGOqOm6NNBUGyT24cxaR6bZu9gZGWQxyu9WWObJ
z6Js78ouyVZZm3kkZXoyghSuxMjnWdShcLqarwvX7TPSPAEnWpu0CvycE+Ty
LLC92hP82qyPiOkxQd3pU8nYOy+/jQtQ7XH0IvTW/JOCk8Du70UZPxkFfbQ8
CsMk8A==
=h1Xt
-----END PGP MESSAGE-----
```

Paste the encrypted message as shown above, press return to go to a new line, press Ctrl+D to finish (Ctrl+Z Windows).

You will be prompted to choose to sign or decrypt the message

`Do you want to sign or decrypt the message?
s=sign, d=decrypt`

Press d and return to decrypt message.

You will be prompted to choose the key slot where your private key is assigned (Only RSA supported currently)

`Enter slot number to use for decryption, 1 - 4 for RSA, 1 - 32 for ECC`

Press number and return to select slot

Follow instructions to enter the challenge code onto the OnlyKey key pad.

`Please enter the 3 digit challenge code on OnlyKey (and press ENTER if necessary)
5 3 2`

If decryption is successful the ASCII armored version and the plaintext version of the message will be displayed. If decryption fails the message "Error with RSA decryption" will be displayed.


### Python client

```python
from onlykey import OnlyKey, Message

# Automatically connect
ok = OnlyKey()

ok.sendmessage(msg=Message.OKGETLABELS)
print ok.read_string()
```
