# python-onlykey

Python client for interacting with the OnlyKey.

OnlyKey-cli - A command line interface to the OnlyKey that can be used for configuration (Similar functionality to [OnlyKey App](https://docs.crp.to/app.html))

## Installation

### Windows Install
1) Python 2.7 and pip are required. To setup a Python environment on Windows we recommend Anaconda https://www.anaconda.com/download/#windows

2) Install Microsoft Visual C++ Compiler for Python http://aka.ms/vcpython27

3)
```
$ pip install onlykey
```


You should see a message showing where the executable is installed.

Installing onlykey-cli-script.py script to c:\Python27\Scripts
Installing onlykey-cli.exe script to c:\Python27\Scripts
Installing onlykey-cli.exe.manifest script to c:\Python27\Scripts

This is usually c:\Python27\Scripts\onlykey-cli.exe

### MacOS Install
Python 2.7 and pip are required. To setup a Python environment on MacOS we recommend Anaconda https://www.anaconda.com/download/#macos

```
$ pip install onlykey
```

### Ubuntu Install with dependencies

```
$ apt update && apt upgrade
$ apt install python-pip python-dev libusb-1.0-0-dev libudev-dev
$ pip install onlykey
```

### Debian Install with dependencies

```
$ apt update && apt upgrade
$ apt install python-pip python-dev libusb-1.0-0-dev libudev-dev
$ pip install onlykey
```

### Fedora/RedHat/CentOS Install with dependencies

```
$ yum update
$ yum install python-pip python-devel libusb-devel libudev-devel \
              gcc redhat-rpm-config
$ pip install onlykey
```
### OpenSUSE Install with dependencies

```
$ zypper install python-pip python-devel libusb-1_0-devel libudev-devel
$ pip install onlykey
```

### Arch Linux Install with dependencies

```
$ sudo pacman -Sy git python2-setuptools python2 libusb python2-pip
$ pip install onlykey
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

## Source

[Python OnlyKey on Github](https://github.com/trustcrypto/python-onlykey)
