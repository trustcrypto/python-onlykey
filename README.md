# python-onlykey

Python client for interacting with the OnlyKey. 

OnlyKey-cli - A command line interface to the OnlyKey that can be used for configuration (Similar functionality to [OnlyKey Chrome App](https://chrome.google.com/webstore/detail/onlykey-configuration/adafilbceehejjehoccladhbkgbjmica?hl=en-US))

OnlyKey-init - A command line tool for setting PIN on OnlyKey (Initial Configuration)

OnlyKey-utils - A command line tool for loading keys.

PGPMessage - Provides a tool for decrypting and signing OpenPGP/GPG messages using OnlyKey. 

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

[OnlyKey CLI](https://github.com/trustcrypto/python-onlykey/releases/download/v0.1-alpha.1/cli)

[OnlyKey PGP Message Tool](https://github.com/trustcrypto/python-onlykey/releases/download/v0.1-alpha.1/PGP_message)

Once the file is downloaded in order to be able to run just by double clicking the file do the following:
1) Open the terminal app and make the file executable with this command:
```
$ chmod +x <location of file you downloaded>
```
2) Right click the file and select "open"

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

The CLI is bundled with the package, it should be present globally after the install (Also available as packaged standalone app "cli").

```
$ onlykey-cli
OnlyKey CLI v0.2
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

Additionally, the CLI can be used to set key labels. Labels 19 - 22 correspond to RSA Keys 1 - 4 and labels 23 - 54 correspond to ECC Keys 1 - 32. In a future version we will add a setkeylabel function to make this transparent to user.

```
$ onlykey-cli
OnlyKey CLI v0.2
Press the right arrow to insert the suggestion.
Press Control-C to retry. Control-D to exit.

OnlyKey> setslot 25 label EmailSigningKey

Successfully set Label

OnlyKey> getkeylabels

Slot RSA Key 1: EmailSigningKey
Slot RSA Key 2: <empty>
Slot RSA Key 3: <empty>
Slot RSA Key 4: <empty>
Slot ECC Key 1: <empty>
Slot ECC Key 2: <empty>
...

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

If you using a previously set RSA private key with decryption capabilitiesyou can decrypt OpenPGP/GPG encrypted email messages:

```
$ PGP_message.py
```

`Do you want to sign or decrypt a message?`
`s = sign, d = decrypt`
```
d

Enter RSA key slot number to use (1 - 4) or enter 0 to list key labels

2

Paste OpenPGP Message, press return to go to new line, and then press Ctrl+D or Ctrl+Z (Windows only)

-----BEGIN PGP MESSAGE-----
Version: Mailvelope v1.7.1
Comment: https://www.mailvelope.com

wcFMA322sr0GLHtKAQ/9Hxs3Fe7vNMGMAphp5ddJCBYSx8aL4N1JRS5O3mrw
KkJfNlHn0YcMoC2J4iMrHTNWj0JeyQiGy5mwstAqL8g5Or8HBuqKTycfhHJV
mfTvXhRTE9WY+0JqYBbg02MjKzYuqrhCKfsu9+T/q58T/75XYE8bYwehsXpJ
2stjIj+wjrRRk4Dx/nGegUAmIAAQPmeizzOwLgJbBSZgK1pfrKwuCOpdxH8v
QRLoX2abpipGhhpkhje2PAtTlX2CGES857KThwFzeAJj94k+VAYfsZOi65gg
yMeF3h8V8KugBnZY9kOJFbi5j84iflvgZa/ZlMzLLHWDhgeYQR7rE/zZxIgL
CjW1Iq2QibM8ug7ri4MfxhrHGN9Ci1EnnIVbMHq4kcPrCr20qouZqbXPuXcG
pJ2eKQahH7Zz9cwNB6FoVgG23z9YYp3Q2tS9Cm9hvzJz+dPvy+OvmVqw4oCF
y4yvFRj82xoL7pDzhAPgeC7d3I4zV2Q9ObV5rQFBe8W1G0eukoS3k/UZJXJO
hIw0VBaYkw0MivKceezk36KhgA4LhNQxiOx0YVk+YYryRC7muyYtRlDoSpGe
1dqI+rBDayvsW4hHu5Y6Sb5N1LnHBZg7OSsz/S5fSAR4lcWpbSF3vyBl3tPQ
mVcbHFgpPjUq71lU31RyqybmkBLdYNNvX8iGeZXWIVTSXgHalMeNCTLiL/yr
JZWTQif+8lfAh3aERtqaJRowOxM/fVutJ7Y+xA+fAEeqzbO8cFvik+ww/8Km
uk2Px9ELdgmlEJQ7IXp1hp46r9tv3lqHmtDyL5t/XL+R7QMjI3Y=
=TBU9
-----END PGP MESSAGE-----
^D

You should see your OnlyKey blink 3 times

Sending the payload to the OnlyKey...

Please enter the 3 digit challenge code on OnlyKey (and press ENTER if necessary)
2 5 2

Trying to read the decrypted data from OnlyKey
For RSA with 4096 keysize this may take up to 9 seconds...

Decoded Decrypted Message = ?3umsg.txtX?E?Secret message that I want to encrypt!?????6?*?gQ?6??m??

Encoded Decrypted Message =
-----BEGIN PGP MESSAGE-----
Version: PGPy v0.4.1

yzN1B21zZy50eHRY1UWaU2VjcmV0IG1lc3NhZ2UgdGhhdCBJIHdhbnQgdG8gZW5j
cnlwdCHTFLG2vRg/NpEq6mdRA8E2sALVbZzA
=Lqt2
-----END PGP MESSAGE-----
```

If decryption is successful the ASCII armored version of the message will be displayed. If decryption fails the message "Error with RSA decryption" will be displayed.

### Sign text email message using OnlyKey

If you using a previously set RSA private key with signing capabilities you can sign text messages in OpenPGP/GPG format:

```
$ PGP_message.py
```

`Do you want to sign or decrypt a message?`
`s = sign, d = decrypt`
```
s

Enter RSA key slot number to use (1 - 4) or enter 0 to list key labels

1
You should see your OnlyKey blink 3 times

Trying to read the public RSA N part 1...

Key Size = 512

Do you want to sign a text message or add signature to a PGP Message?
t = text message, p = PGP Message

t

Type or paste the text message, press return to go to new line, and then press Ctrl+D or Ctrl+Z (Windows only)

this message is from me!

You should see your OnlyKey blink 3 times

Sending the payload to the OnlyKey...

Please enter the 3 digit challenge code on OnlyKey (and press ENTER if necessary)
4 2 3

Trying to read the signature from OnlyKey
For RSA with 4096 keysize this may take up to 9 seconds...

Encoded Signed Message =
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

this message is from me!
-----BEGIN PGP SIGNATURE-----
Version: PGPy v0.4.1

wsFcBAABCAAGBQJY1UMbAAoJEFrjcMPEcl4WjCwP/0OMg9+Jll3b0r5l6Xbz/0uR
ofW0NUC7jIcv/VJeGdF92aQrreeFcSLGJmQtOfDOIfxZUJ5fMq9jZapomEounVIy
oEha/FWVGOyiK4OznSgBtkq2DUj3QQjp/tmQf7rAnYiliO6BOkTiJmib8CZaZTXx
rbQEiLm7kUa4VFoYsum3qS6e2eICfZb/A45XMBjra0PhbZH8Et51IWCT52ighGP8
LAE2s5U+2eLLXad/95QB3w9VaGtZmUvrEPb0vlOSeI6Wj/6aDde9+t1eZUAhsdwD
AndKfCvoapGd3KV0JwkXg6OTr2U/cE5DHBpFYYHjeWmKcLs09v0O7BwcXSwY62UL
0kddPiIxTU+AgPeK+A+xdsvZ6+j1ZZNZVMEG4RKFQnKignSSUR3AmkNQNAemzdBp
Ki18Nl26zSuj5le+I5QjlGNJ8QSieXNGmbjlnj4GMNxCgM2XR6OmaK63oDkS/xp+
ECd8yjzPWx5pDuYMEDKGvv8iw0kNe/b5ZYUTDhvZxlUeL5RtDzdAi2x4vVT8mbmu
/lbnuy8A01geQEFsbMk+4ON9MktjvezYPbjNUGrhBxFqd2XKhIIwSueghdOym/Xr
q6ZOiNRpqxG2aiRZ4flDn01qlYrtpGxLyQowxo4DVeBOTfPY0y+s7ni6KVadAFkd
nHlZ6TZaI4Awu6b9tIAR
=1llp
-----END PGP SIGNATURE-----
```

If signature is successful the ASCII armored version of the message will be displayed. If signature fails the message "Error with RSA signature" will be displayed.

### Add a signature to a PGP message using OnlyKey

If you using a previously set RSA private key with signing capabilities you can sign text messages in OpenPGP/GPG format:

```
$ PGP_message.py
```

`Do you want to sign or decrypt a message?`
`s = sign, d = decrypt`
```
s

Enter RSA key slot number to use (1 - 4) or enter 0 to list key labels

1

You should see your OnlyKey blink 3 times

Key Size = 512


Do you want to sign a text message or add signature to a PGP Message?
t = text message, p = PGP Message

p

Paste OpenPGP Message, press return to go to new line, and then press Ctrl+D or Ctrl+Z (Windows only)

-----BEGIN PGP MESSAGE-----
Version: PGPy v0.4.1

yzN1B21zZy50eHRY1UWaU2VjcmV0IG1lc3NhZ2UgdGhhdCBJIHdhbnQgdG8gZW5j
cnlwdCHTFLG2vRg/NpEq6mdRA8E2sALVbZzA
=Lqt2
-----END PGP MESSAGE-----
^D

You should see your OnlyKey blink 3 times

Please enter the 3 digit challenge code on OnlyKey (and press ENTER if necessary)
3 2 4

Trying to read the signature from OnlyKey
For RSA with 4096 keysize this may take up to 9 seconds...

Encoded Signed Message =
-----BEGIN PGP MESSAGE-----
Version: PGPy v0.4.1

yzN1B21zZy50eHRY1UWaU2VjcmV0IG1lc3NhZ2UgdGhhdCBJIHdhbnQgdG8gZW5j
cnlwdCHTFLG2vRg/NpEq6mdRA8E2sALVbZzA
=Lqt2
-----END PGP MESSAGE-----
-----BEGIN PGP MESSAGE-----
Version: PGPy v0.4.1

xA0DAAgBX/X2Pr84qJgAyzN1B21zZy50eHRY1UWaU2VjcmV0IG1lc3NhZ2UgdGhh
dCBJIHdhbnQgdG8gZW5jcnlwdCHTFLG2vRg/NpEq6mdRA8E2sALVbZzAwsFcBAAB
CAAGBQJY1UciAAoJEF/19j6/OKiY67AQAKwEsTOvYr98S8QMxXoV1d3sUQDu0mCM
7fASd10YR6YRHq2jcvy/D9+ZRc0dlZdUj+3GjbYbrxe10GeB0+EeJnCpaALLvfFm
2+9XmM/w3KFHE2pAe+gvN8s2+hP8i7UWRRgcFQCSLvr+VP1yhfG0O7qdMnYgl6A7
3TXPk4+PnH5qbuWiDDrl9XfdDw4wtFWOxRwq+GXM4hgLU4datouv3cmJA0ikY3Uw
BIgxSP+Hv6ku94tOlACu0R4jOzq+jQBkgWkVViYlNCOS4EdaU9776wrhKIjRuibd
yzerkZlMj91GrThC9Ox/sEbmoXpoa79Z8qXZi2wJ4AqNi4xnEUdtkGFgZaaJUsDn
bbPlNLxictjcqFk9Q2LasbtAOT+f6yD4YgNqBV33fbZXVFiXgYdxqKb0BrcJBCQQ
LcvrazK1byvdBCDiaoHatavaqKKjK9Fs3pCtm0jEfAaiSQStCMF4jRUGOxGWeRav
kaCP7MvGtsNiR3kjDXO9Y79KNNn0ID/AZ9/Z9Ho1wSwUe95BG+WixaFcwz0KlDbZ
bVV0mkPX7/orqD2ihVvmXXB9VcdXn6oKsNA2gBUQp4a80NnvGnh4bdtXoypZkNoe
3bXNvRAne0kSPxjNzhBjJF9F1/EgjR0gHzi677AuhrRN1CkdaHLnnopBjkUmtU+0
BNBU7972zW9q
=9w/g
-----END PGP MESSAGE-----
```
If signature is successful the ASCII armored version of the message will be displayed. If signature fails the message "Error with RSA signature" will be displayed.
