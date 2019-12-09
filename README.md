# python-onlykey

Python client for interacting with the OnlyKey.

OnlyKey-cli - A command line interface to the OnlyKey that can be used for configuration (Similar functionality to [OnlyKey App](https://docs.crp.to/app.html))

<!---
PGPMessage - **Still in early development.** - Provides a tool for decrypting and signing OpenPGP/GPG messages using OnlyKey (python only OpenPGP implementation).



## Run without installation (Packaged App)

### Mac OS Run without installation

Tested on El Capitan

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

### Windows Run without installation

Coming soon

## Installation

### Windows Dependencies

Python 2.7 - https://www.python.org/downloads/release/python-2713/

git - https://git-scm.com/download/win

## Mac OS Install

Tested on Sierra
```
sudo pip uninstall crypto
sudo pip uninstall pycrypto
easy_install pycrypto
```
--->

## Installation

### Windows Install
1) Python 2.7 and pip are required. To setup a Python environment on Windows we recommend Anaconda https://www.anaconda.com/download/#windows

2) Install Microsoft Visual C++ Compiler for Python http://aka.ms/vcpython27

3)
```
$ pip2 install onlykey
```


You should see a message showing where the executable is installed.

Installing onlykey-cli-script.py script to c:\Python27\Scripts
Installing onlykey-cli.exe script to c:\Python27\Scripts
Installing onlykey-cli.exe.manifest script to c:\Python27\Scripts

This is usually c:\Python27\Scripts\onlykey-cli.exe

### MacOS Install
Python 2.7 and pip are required. To setup a Python environment on MacOS we recommend Anaconda https://www.anaconda.com/download/#macos

```
$ pip2 install onlykey
```

### Ubuntu Install with dependencies

```
$ apt update && apt upgrade
$ apt install python-pip python-dev libusb-1.0-0-dev libudev-dev
$ pip2 install onlykey
```

### Debian Install with dependencies

```
$ apt update && apt upgrade
$ apt install python-pip python-dev libusb-1.0-0-dev libudev-dev
$ pip2 install onlykey
```

### Fedora/RedHat/CentOS Install with dependencies

```
$ yum update
$ yum install python-pip python-devel libusb-devel libudev-devel \
              gcc redhat-rpm-config
$ pip2 install onlykey
```
### OpenSUSE Install with dependencies

```
$ zypper install python-pip python-devel libusb-1_0-devel libudev-devel
$ pip2 install onlykey
```

### Arch Linux Install with dependencies

```
$ sudo pacman -Sy git python2-setuptools python2 libusb python2-pip
$ pip2 install onlykey
```

### FreeBSD Install with dependencies

See forum thread - https://groups.google.com/forum/#!category-topic/onlykey/new-features-and-feature-requests/CEYwdXjB508

### Linux UDEV Rule

In order for non-root users in Linux to be able to communicate with OnlyKey a udev rule must be created as described [here](https://docs.crp.to/linux).


## QuickStart

### Command Options

- init - A command line tool for setting PIN on OnlyKey (Initial Configuration)

- settime - A command for setting time on OnlyKey, time is needed for TOTP (Google Authenticator)

- getlabels - Returns slot labels

- getkeylabels - Returns key labels for RSA keys 1-4 and ECC keys 1 -32

- setslot [id] [type] [value]
  - [id] must be slot number 1a - 6b
  - [type] must be one of the following:
    - label - Slot label i.e. My Google Acct
    - url - URL to login page
    - delay1 - set a 0 - 9 second delay
    - add_char1 - Additional character before username 1 for TAB, 0 to clear
    - username - Username to login
    - add_char2 - Additional character after username 1 for TAB, 2 for RETURN
    - delay2 - set a 0 - 9 second delay
    - password - Password to login
    - add_char3 - Additional character after password 1 for TAB, 2 for RETURN
    - delay3 - set a 0 - 9 second delay
    - add_char4 - Additional character before OTP 1 for TAB
    - 2fa - type of two factor authentication
      - g - Google Authenticator
      - y - Yubico OTP
      - u - U2F
    - totpkey - Google Authenticator key
    - add_char5 - Additional character after OTP 2 for RETURN

- wipeslot <id>
  - <id> must be slot number 1a - 6b

- backupkey - Generates a backup key in key slot 32 and returns the generated private key

- idletimeout - OnlyKey locks after ideletimeout is reached (1 – 255 minutes; default = 30; 0 to disable)

- wipemode - Configure how the OnlyKey responds to
a factory reset. WARNING - Setting to Full Wipe mode cannot be changed.
  - 1 - Sensitive Data Only (default)
All sensitive data is wiped.
  - 2 - Full Wipe (recommended for plausible deniability users) Entire device is wiped. Firmware must be reloaded.

- keylayout - Set keyboard layout
  - 1 - USA_ENGLISH	(Default)
  - 2 - CANADIAN_FRENCH
  - 3 - CANADIAN_MULTILINGUAL
  - 4 - DANISH
  - 5 - FINNISH
  - 6 - FRENCH
  - 7 - FRENCH_BELGIAN
  - 8 - FRENCH_SWISS
  - 9 - GERMAN
  - 10 - GERMAN_MAC
  - 11 - GERMAN_SWISS
  - 12 - ICELANDIC
  - 13 - IRISH
  - 14 - ITALIAN
  - 15 - NORWEGIAN
  - 16 - PORTUGUESE
  - 17 - PORTUGUESE_BRAZILIAN
  - 18 - SPANISH
  - 19 - SPANISH_LATIN_AMERICA
  - 20 - SWEDISH
  - 21 - TURKISH
  - 22 - UNITED_KINGDOM
  - 23 - CZECH
  - 24 - SERBIAN_LATIN_ONLY

- keytypespeed - 1 = slowest; 10 = fastest [4 = default]

### Running Commands

You can run commands in two ways:

**1) Directly in terminal**

Like this:

```
$ onlykey-cli getlabels

Slot 1a:
Slot 1b:

Slot 2a:
Slot 2b:

Slot 3a:
Slot 3b:

Slot 4a:
Slot 4b:

Slot 5a:
Slot 5b:

Slot 6a:
Slot 6b:

$ onlykey-cli setslot 1a label ok
Successfully set Label
$ onlykey-cli getlabels

Slot 1a: ok
Slot 1b:

Slot 2a:
Slot 2b:

Slot 3a:
Slot 3b:

Slot 4a:
Slot 4b:

Slot 5a:
Slot 5b:

Slot 6a:
Slot 6b:

```

**2) Interactive Mode**

Or you can run commands in an interactive shell like this:

```
$ onlykey-cli
OnlyKey CLI v0.2
Press the right arrow to insert the suggestion.
Press Control-C to retry. Control-D to exit.

OnlyKey> getlabels

Slot 1a:
Slot 1b:

Slot 2a:
Slot 2b:

Slot 3a:
Slot 3b:

Slot 4a:
Slot 4b:

Slot 5a:
Slot 5b:

Slot 6a:
Slot 6b:

OnlyKey> setslot 1a label ok

Successfully set Label

OnlyKey> getlabels

Slot 1a: ok
Slot 1b:

Slot 2a:
Slot 2b:

Slot 3a:
Slot 3b:

Slot 4a:
Slot 4b:

Slot 5a:
Slot 5b:

Slot 6a:
Slot 6b:

OnlyKey> setslot 1a url accounts.google.com

Successfully set URL

OnlyKey> setslot 1a add_char1 2

Successfully set Character1

OnlyKey> setslot 1a delay1 2

Successfully set Delay1

OnlyKey> setslot 1a username onlykey.1234

Successfully set Username

OnlyKey> setslot 1a add_char2 2

Successfully set Character2

OnlyKey> setslot 1a delay2 2

Successfully set Delay2

OnlyKey> setslot 1a password

Type Control-T to toggle password visible.
Password: *********
Successfully set Password

OnlyKey> setslot 1a add_char3 2

Successfully set Character3

OnlyKey> setslot 1a delay3 2

Successfully set Delay3

OnlyKey> setslot 1a 2fa g

Successfully set 2FA Type

OnlyKey> setslot 1a totpkey

Type Control-T to toggle password visible.
Password: ********************************
Successfully set TOTP Key

OnlyKey> setslot 1a add_char4 2

Successfully set Character4

OnlyKey>

Bye!
```
<!---
### Decrypt PGP email messages using OnlyKey

If you using a previously set RSA private key with decryption capabilities you can decrypt OpenPGP/GPG encrypted email messages:

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

## PGPMessage Support

Install w/PGPMessage support. Requires Python 2.7 and Git.

```
$ git clone https://github.com/trustcrypto/python-onlykey.git --recursive
$ cd python-onlykey
$ pip2 install .
$ cd PGPy
$ pip2 install .
$ cd ..
```
--->
## Source

[Python OnlyKey on Github](https://github.com/trustcrypto/python-onlykey)
