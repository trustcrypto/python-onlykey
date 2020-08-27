# python-onlykey

Python client for interacting with the OnlyKey.

OnlyKey-cli - A command line interface to the OnlyKey that can be used for configuration (Similar functionality to [OnlyKey App](https://docs.crp.to/app.html))


## Installation

### Windows Install with dependencies
1) Python 3.8 and pip3 are required. To setup a Python environment on Windows we recommend Anaconda [https://www.anaconda.com/download/#windows](https://www.anaconda.com/download/#windows)

2)
```
$ pip3 install onlykey
```

You should see a message showing where the executable is installed.

Installing onlykey-cli-script.py script to c:\Python37\Scripts
Installing onlykey-cli.exe script to c:\Python37\Scripts
Installing onlykey-cli.exe.manifest script to c:\Python37\Scripts

This is usually c:\Python37\Scripts\onlykey-cli.exe

### MacOS Install with dependencies
Python 3.8 and pip3 are required. To setup a Python environment on MacOS we recommend Anaconda [https://www.anaconda.com/download/#macos](https://www.anaconda.com/download/#macos)
```
$ brew install libusb
$ pip3 install onlykey
```

### Ubuntu Install with dependencies
```
$ sudo apt update && apt upgrade
$ sudo apt install python3-pip python3-tk libusb-1.0-0-dev libudev-dev
$ pip3 install onlykey
$ wget https://raw.githubusercontent.com/trustcrypto/trustcrypto.github.io/master/49-onlykey.rules
$ sudo cp 49-onlykey.rules /etc/udev/rules.d/
$ sudo udevadm control --reload-rules && udevadm trigger
```

### Debian Install with dependencies
```
$ sudo apt update && apt upgrade
$ sudo apt install python3-pip python3-tk libusb-1.0-0-dev libudev-dev
$ pip3 install onlykey
$ wget https://raw.githubusercontent.com/trustcrypto/trustcrypto.github.io/master/49-onlykey.rules
$ sudo cp 49-onlykey.rules /etc/udev/rules.d/
$ sudo udevadm control --reload-rules && udevadm trigger
```

### RedHat Install with dependencies
```
$ yum update
$ yum install python3-pip python3-devel python3-tk libusb-devel libudev-devel \
              gcc redhat-rpm-config
$ pip3 install onlykey
$ wget https://raw.githubusercontent.com/trustcrypto/trustcrypto.github.io/master/49-onlykey.rules
$ sudo cp 49-onlykey.rules /etc/udev/rules.d/
$ sudo udevadm control --reload-rules && udevadm trigger
```

### Fedora Install with dependencies
```
$ dnf install python3-pip python3-devel python3-tkinter libusb-devel libudev-devel \
              gcc redhat-rpm-config
$ pip3 install onlykey
$ wget https://raw.githubusercontent.com/trustcrypto/trustcrypto.github.io/master/49-onlykey.rules
$ sudo cp 49-onlykey.rules /etc/udev/rules.d/
$ sudo udevadm control --reload-rules && udevadm trigger
```

### OpenSUSE Install with dependencies
```
$ zypper install python3-pip python3-devel python3-tk libusb-1_0-devel libudev-devel
$ pip3 install onlykey
$ wget https://raw.githubusercontent.com/trustcrypto/trustcrypto.github.io/master/49-onlykey.rules
$ sudo cp 49-onlykey.rules /etc/udev/rules.d/
$ sudo udevadm control --reload-rules && udevadm trigger
```

### Arch Linux Install with dependencies
```
$ sudo pacman -Sy git python3-setuptools python3 libusb python3-pip
$ pip3 install onlykey
$ wget https://raw.githubusercontent.com/trustcrypto/trustcrypto.github.io/master/49-onlykey.rules
$ sudo cp 49-onlykey.rules /etc/udev/rules.d/
$ sudo udevadm control --reload-rules && udevadm trigger
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

- wipeslot [id]
  - <id> must be slot number 1a - 6b

- setkey [key slot] [key type]
  - See examples [here](https://docs.crp.to/command-line.html#writing-private-keys-and-passwords)  

- wipekey [key slot]

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
  - 25 - HUNGARIAN

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
OnlyKey CLI v1.2.2
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

## Writing Private Keys and Passwords

Keys/passwords are masked when entered and should only be set from interactive mode and not directly from terminal. Entering directly from terminal is not secure as command history is stored.

**Setkey Examples**

To set key a device must first be put into config mode.

- Set HMAC key 1 to a custom value
```
$ onlykey-cli

OnlyKey> setkey 130 0                                                                                                     

Type Control-T to toggle password visible.
Password/Key: ****************************************  
```

*HMAC key must be 20 bytes, 130 is mapped to HMAC slot 1, 0 is HMAC type*

- Set HMAC key 2 to a custom value
```
$ onlykey-cli

OnlyKey> setkey 129 0                                                                                                     

Type Control-T to toggle password visible.
Password/Key: ****************************************  
```

*HMAC key must be 20 bytes, 129 is mapped to HMAC slot 2, 0 is HMAC type*

- Set ECC key in slot 101 to a custom value (Slots 101-116 are available for ECC keys. Supported ECC curves X25519(1), NIST256P1(2), SECP256K1(3))
```
$ onlykey-cli

OnlyKey> setkey 101 1                                                                                                     

Type Control-T to toggle password visible.
Password/Key: *************************************************************  
```

*ECC key must be 32 bytes, 1 is X25519 type*

## Scripting Example

- Set time on OnlyKey (required for TOTP)

```
$ onlykey-cli settime
```
This can be added to scripts such as the UDEV rule to automatically set time when device is inserted into USB port. See example here https://raw.githubusercontent.com/trustcrypto/trustcrypto.github.io/master/49-onlykey.rules

- Scripted provisioning of an OnlyKey slots and keys can be done by creating a script that sets multiple values on OnlyKey

## Source

[Python OnlyKey on Github](https://github.com/trustcrypto/python-onlykey)
