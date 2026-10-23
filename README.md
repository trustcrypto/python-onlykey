# onlykey-cli

OnlyKey-cli - A command line interface to the OnlyKey (Similar functionality to [OnlyKey App](https://docs.crp.to/app.html)) that can be used for configuration, scripting, and testing.

## Installation

### Windows Stand-Alone EXE
No install is required. Download and run the EXE to open OnlyKey CLI interactive mode or run directly from command line like this:
```
C:\ onlykey-cli.exe getlabels
```

[Download here](https://github.com/trustcrypto/python-onlykey/releases/download/v1.2.5/onlykey-cli.exe)

### Windows Install with dependencies
1) Python 3.10 or newer and pip3 are required. To setup a Python environment on Windows we recommend Anaconda [https://www.anaconda.com/download/#windows](https://www.anaconda.com/download/#windows)

2) From an administrator command prompt run:
```
pip3 install hidapi==0.9.0 onlykey
```

You should see a message showing where the executable is installed. This is usually c:\python39\scripts\onlykey-cli.exe

### MacOS Install with dependencies
Python 3.10 or newer and pip3 are required. To setup a Python environment on MacOS we recommend Anaconda [https://www.anaconda.com/download/#macos](https://www.anaconda.com/download/#macos)
```
$ brew install libusb
$ pip3 install onlykey
```

### Linux/BSD Install with dependencies

In order for non-root users in Linux to be able to communicate with OnlyKey a udev rule must be created as described [here](https://docs.crp.to/linux).

#### Ubuntu Install with dependencies
```
$ sudo apt update && sudo apt upgrade
$ sudo apt install python3-pip python3-tk libusb-1.0-0-dev libudev-dev
$ pip3 install onlykey
$ wget https://raw.githubusercontent.com/trustcrypto/trustcrypto.github.io/master/49-onlykey.rules
$ sudo cp 49-onlykey.rules /etc/udev/rules.d/
$ sudo udevadm control --reload-rules && udevadm trigger
```

#### Debian Install with dependencies
```
$ sudo apt update && sudo apt upgrade
$ sudo apt install python3-pip python3-tk libusb-1.0-0-dev libudev-dev
$ pip3 install onlykey
$ wget https://raw.githubusercontent.com/trustcrypto/trustcrypto.github.io/master/49-onlykey.rules
$ sudo cp 49-onlykey.rules /etc/udev/rules.d/
$ sudo udevadm control --reload-rules && udevadm trigger
```

#### RedHat Install with dependencies
```
$ yum update
$ yum install python3-pip python3-devel python3-tk libusb-devel libudev-devel \
              gcc redhat-rpm-config
$ pip3 install onlykey
$ wget https://raw.githubusercontent.com/trustcrypto/trustcrypto.github.io/master/49-onlykey.rules
$ sudo cp 49-onlykey.rules /etc/udev/rules.d/
$ sudo udevadm control --reload-rules && udevadm trigger
```

#### Fedora Install with dependencies
```
$ dnf install python3-pip python3-devel python3-tkinter libusb-devel libudev-devel \
              gcc redhat-rpm-config
$ pip3 install onlykey
$ wget https://raw.githubusercontent.com/trustcrypto/trustcrypto.github.io/master/49-onlykey.rules
$ sudo cp 49-onlykey.rules /etc/udev/rules.d/
$ sudo udevadm control --reload-rules && udevadm trigger
```

#### OpenSUSE Install with dependencies
```
$ zypper install python3-pip python3-devel python3-tk libusb-1_0-devel libudev-devel
$ pip3 install onlykey
$ wget https://raw.githubusercontent.com/trustcrypto/trustcrypto.github.io/master/49-onlykey.rules
$ sudo cp 49-onlykey.rules /etc/udev/rules.d/
$ sudo udevadm control --reload-rules && udevadm trigger
```

#### Arch Linux Install with dependencies
```
$ sudo pacman -Syu git python3-setuptools python3 libusb python3-pip
$ pip3 install onlykey
$ wget https://raw.githubusercontent.com/trustcrypto/trustcrypto.github.io/master/49-onlykey.rules
$ sudo cp 49-onlykey.rules /etc/udev/rules.d/
$ sudo udevadm control --reload-rules && udevadm trigger
```

#### FreeBSD Install with dependencies

See forum thread [here](https://groups.google.com/d/msg/onlykey/CEYwdXjB508/MCe14p0gAwAJ)

## QuickStart

Usage: onlykey-cli [OPTIONS]

### Setup Options

#### init
A command line tool for setting PIN on OnlyKey (Initial Configuration)

### General Options

#### version
Displays the version of the app

#### capabilities
Asks the firmware what it supports (needs firmware with protocol v1 or later): firmware version,
key types, build flags (PQC, DUO, debug, whether the no-press user input mode is compiled in) and
the user input modes each of derivedkeymode / storedkeymode / webderivemode accepts. Older
firmware prints that it does not report capabilities.

#### fwversion
Displays the version of the OnlyKey firmware

#### wink
OnlyKey flashes blue (winks), may be used for visual confirmation of connectivity

#### getlabels
Returns slot labels

#### settime
A command for setting time on OnlyKey, time is needed for TOTP (Google Authenticator)

#### getkeylabels
Returns key labels for RSA keys 1-4 and ECC keys 1-16

#### rng [type]
Access OnlyKey TRNG to generate random numbers:
- [type] must be one of the following:
  - hexbytes - Output hex encoded random bytes. Default 8 bytes; Maximum 255 bytes. Specify number of bytes to return with --count <number of bytes> i.e. 'onlykey-cli rng hexbytes --count 32'
  - feedkernel - Feed random bytes to /dev/random.

### OnlyKey Preferences Options

#### idletimeout [num]
OnlyKey locks after ideletimeout is reached (1 – 255 minutes; default = 30; 0 to disable). [More info](https://docs.crp.to/usersguide.html#configurable-inactivity-lockout-period)

#### wipemode [num]
Configure how the OnlyKey responds to
a factory reset. WARNING - Setting to Full Wipe mode cannot be changed.
1 = Sensitive Data Only (default); 2 = Full Wipe (recommended for plausible deniability users) Entire device is wiped. Firmware must be reloaded. [More info](https://docs.crp.to/usersguide.html#configurable-wipe-mode)

#### keylayout [num]
Set keyboard layout
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
  - 23 - US_INTERNATIONAL
  - 24 - CZECH
  - 25 - SERBIAN_LATIN_ONLY
  - 26 - HUNGARIAN
  - 27 - DANISH MAC
  - 28 - US_DVORAK

[More info](https://docs.crp.to/usersguide.html#configurable-keyboard-layouts)

#### keytypespeed [num]
1 = slowest; 10 = fastest [7 = default]
[More info](https://docs.crp.to/usersguide.html#configurable-keyboard-type-speed)

#### ledbrightness [num]
1 = dimmest; 10 = brightest [8 = default]
[More info](https://docs.crp.to/usersguide.html#configurable-led-brightness)

#### touchsense [num]
Change the OnlyKey's button touch sensitivity.
WARNING: Setting button's touch sensitivity lower than 5 is not recommended as this could result in inadvertent button press.
2 = highest sensitivity; 100 = lowest sensitivity [12 = default]

#### storedkeymode [num]
User input required to use a stored key (RSA slots 1-4, ECC slots 101-132 - any protocol: SSH, PGP, age, composite PQC)
0 = Challenge Code Required; 1 = Button Press Required (default); 2 = No press (unattended agents - only honoured by firmware built with OK_ALLOW_NO_PRESS, refused otherwise)
[More info](https://docs.crp.to/usersguide.html#stored-challenge-mode)

#### derivedkeymode [num]
User input required to use a derived key (SSH/GPG agent identities)
0 = Challenge Code Required; 1 = Button Press Required (default); 2 = No press (as above)
[More info](https://docs.crp.to/usersguide.html#derived-challenge-mode)

#### webderivemode [num]
User input required to use a web derived key - the OnlyKey web app / OnlyAgent in the browser, and derived X-Wing age decrypt via age-plugin-onlykey. The key itself never changes with this setting.
0 = Challenge Code Required (the web app / age plugin shows the 3 digits); 1 = Button Press Required (default); 2 = No press (press-free per-site decryption)

#### webcryptpolicy [num]
What the OnlyKey web app (apps.crp.to / apps.onlykey.io) may do with this OnlyKey. Requires firmware v3.1.0 or newer and config mode.
0 = Derived keys only (stored keys / PGP not available to the web app); 1 = Also allow stored keys (PGP) from the web app; 2 = Turn the web app extension off entirely; 3 = Both bits
Until this is set the key behaves as older firmware did: the web app may use stored keys.

#### hmackeymode [num]
Enable or disable button press for HMAC challenge-response
0 = Button Press Required (default); 1 = Button Press Not Required.
[More info](https://docs.crp.to/usersguide.html#hmac-mode)

#### backupkeymode [num]
1 = Lock backup key so this may not be changed on device
WARNING - Once set to "Locked" this cannot be changed unless a factory reset occurs.
[More info](https://docs.crp.to/usersguide.html#backup-key-mode)

#### sysadminmode
Enable or disable challenge for stored keys (SSH/PGP)
0 = Challenge Code Required (default); 1 = Button Press Required
[More info](https://docs.crp.to/usersguide.html#derived-challenge-mode)

#### lockbutton
One of the buttons on OnlyKey can be configured as a lock button.
0 = Disable lockbutton; 1-6 = The selected button
[More info](https://docs.crp.to/usersguide.html#configurable-lock-button)

### Slot Config Options

#### setslot [id] [type] [value]
  - [id] must be slot number 1a - 6b
  - [type] must be one of the following:
    - label - set slots (1a - 6b) to have a descriptive label i.e. My Google Acct
    - url - URL to login page
    - delay1 - set a 0 - 9 second delay
    - addchar1 - Additional character before username 1 for TAB, 0 to clear
    - username - Username to login
    - addchar2 - Additional character after username 1 for TAB, 2 for RETURN
    - delay2 - set a 0 - 9 second delay
    - password - Password to login
    - addchar3 - Additional character after password 1 for TAB, 2 for RETURN
    - delay3 - set a 0 - 9 second delay
    - addchar4 - Additional character before OTP 1 for TAB
    - 2fa - type of two factor authentication
      - g - Google Authenticator
      - y - Yubico OTP
      - u - U2F
    - totpkey - Google Authenticator key
    - addchar5 - Additional character after OTP 2 for RETURN

#### wipeslot [id]
  - [id] must be slot number 1a - 6b

### Key Config Options

#### setkey [key slot] [type] [features] [hex key]
Sets raw private keys and key labels, to set PEM format keys use the OnlyKey App
  - [key slot] must be key number RSA1 - RSA4, PQC1 - PQC4, ECC1 - ECC16, HMAC1 - HMAC2
  - [type] must be one of the following:
    - label - set to have a descriptive key label i.e. My GPG signing key
    - p - Composite PQC PGP seed blob (160 bytes; PQC1 - PQC4 only, see loadpqc)
    - x - Ed25519 Key Type (32 bytes, signing)
    - n - NIST256P1 Key Type (32 bytes)
    - s - SECP256K1 Key Type (32 bytes)
    - c - X25519 (Curve25519) Key Type (32 bytes, decryption only)
    - m - ML-KEM-768 seed (64 bytes, decryption only)
    - w - X-Wing seed (32 bytes, decryption only)
    - 2 - RSA Key Type 2048bits (256 bytes)
    - 4 - RSA Key Type 4096bits (512 bytes)
    - h - HMAC Key Type (20 bytes)
  - [features] must be one of the following:
    - s - Use for signing
    - d - Use for decryption
    - b - Use for encryption/decryption of backups
  - For setting keys see examples [here](https://docs.crp.to/command-line.html#writing-private-keys-and-passwords).

#### genkey [key slot] [type] [features]
Generates random private key on device
  - [key slot] must be key number ECC1 - ECC16 (only ECC keys supported)
  - [type] must be one of the following:
    - x - Ed25519 Key Type
    - n - NIST256P1 Key Type
    - s - SECP256K1 Key Type
    - c - X25519 (Curve25519) Key Type
    - m - ML-KEM-768 Key Type
    - w - X-Wing Key Type
  - [features] must be one of the following:
    - s - Use for signing
    - d - Use for decryption
    - b - Use for encryption/decryption of backups
  - For generating key see example [here](https://docs.crp.to/command-line.html#writing-private-keys-and-passwords).

#### loadpqc [keyfile] [PQC1-PQC4] [passphrase]
Loads a composite post-quantum PGP private key (ML-KEM-768 + X25519 / ML-DSA-65 + Ed25519, IETF OpenPGP-PQC) from an armored key file into one of the four PQC slots (the RSA slots). Requires firmware v3.1.0 or newer, config mode, and **Node.js** on PATH (the key file is parsed with the bundled OpenPGP.js). A raw 160-byte seed blob can instead be loaded with `setkey PQC1 p [hex]`.

#### wipekey [key id]
Erases key stored at [key id]
  - [key id] must be key number RSA1 - RSA4, PQC1 - PQC4, ECC1 - ECC16, HMAC1 - HMAC2

### age plugin (age-plugin-onlykey)
Installed with `pip3 install "onlykey[age]"`. Lets [age](https://age-encryption.org) encrypt to and decrypt with an OnlyKey using X-Wing (ML-KEM-768 + X25519) keys. Requires firmware v3.1.0 or newer.
  - `age-plugin-onlykey --generate` - generate an X-Wing key on the device
  - `age-plugin-onlykey --identity` / `--recipient` - print the identity file line / the recipient for a stored key
  - `age-plugin-onlykey --derived --label NAME --recipient` - a derived recipient for a label; the private key never leaves the device and the same label gives the same recipient in the OnlyKey web app

### FIDO2 Config Options

#### ping
Sends a FIDO2 transaction to the device, which immediately echoes the same data back. This command is defined to be a uniform function for debugging, latency and performance measurements (CTAPHID_PING).

#### set-pin
Set new FIDO PIN, this is the PIN entered via keyboard and used for FIDO2 register/login (not the OnlyKey PIN entered on device).

#### change-pin
Change FIDO PIN, this is the PIN entered via keyboard and used for FIDO2 register/login (not the OnlyKey PIN entered on device, to change that PIN use the OnlyKey Desktop App).

#### credential [operation] [credential ID]
   - [operation] must be one of the following:
     - info - Display number of existing resident keys and remaining space.
     - ls - List resident keys.
     - rm [credential ID] - Remove resident keys, [example here](https://docs.crp.to/command-line.html#list-and-remove-fido2-resident-key).

#### reset
Reset wipes all FIDO U2F and FIDO2 credentials!!! It is highly recommended to backup device prior to reset.

### Running Command Options

You can run commands in two ways:

#### 1) Directly in terminal

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

#### 2) Interactive Mode

Or you can run commands in an interactive shell like this:

```
$ onlykey-cli
OnlyKey CLI v1.2.10
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

OnlyKey> setslot 1a addchar1 2

Successfully set Character1

OnlyKey> setslot 1a delay1 2

Successfully set Delay1

OnlyKey> setslot 1a username onlykey.1234

Successfully set Username

OnlyKey> setslot 1a addchar2 2

Successfully set Character2

OnlyKey> setslot 1a delay2 2

Successfully set Delay2

OnlyKey> setslot 1a password

Type Control-T to toggle password visible.
Password: *********
Successfully set Password

OnlyKey> setslot 1a addchar3 2

Successfully set Character3

OnlyKey> setslot 1a delay3 2

Successfully set Delay3

OnlyKey> setslot 1a 2fa g

Successfully set 2FA Type

OnlyKey> setslot 1a totpkey

Type Control-T to toggle password visible.
Password: ********************************
Successfully set TOTP Key

OnlyKey> setslot 1a addchar4 2

Successfully set Character4

OnlyKey>

Bye!
```

## Examples

### Writing Private Keys and Passwords

Keys/passwords are masked when entered and should only be set from interactive mode and not directly from terminal. Entering directly from terminal is not secure as command history is stored.


**Setkey Examples**

To set key a device must first be put into config mode.


**Set HMAC key 1 to a custom value**

$ onlykey-cli

OnlyKey> setkey HMAC1 h                                                                                                  

Type Control-T to toggle password visible.
Password/Key: ****************************************  

Successfully set ECC Key

*HMAC key must be 20 bytes, h is HMAC type*


**Set HMAC key 2 to a custom value**

$ onlykey-cli

OnlyKey> setkey HMAC2 h                                                                                                     

Type Control-T to toggle password visible.
Password/Key: ****************************************  

Successfully set ECC Key

*HMAC key must be 20 bytes, h is HMAC type*


**Set ECC key in slot ECC1 to a custom value (Slots ECC1-ECC16 are available for ECC keys. Supported ECC curves X25519(x), NIST256P1(n), SECP256K1(s))**

$ onlykey-cli

OnlyKey> setkey ECC1 x                                                                                                    

Type Control-T to toggle password visible.
Password/Key: *************************************************************  

Successfully set ECC Key

*ECC key must be 32 bytes, x is X25519 type*

**Genkey Examples**

To set key a device must first be put into config mode.

**Generate ECC key in slot ECC1 to a custom value (Slots ECC1-ECC16 are available for ECC keys. Supported ECC curves X25519(x), NIST256P1(n), SECP256K1(s))**

$ onlykey-cli

OnlyKey> genkey ECC1 x                                                                                                    

Successfully set ECC Key


### Scripting Example


**Set time on OnlyKey (required for TOTP)**

$ onlykey-cli settime

This can be added to scripts such as the UDEV rule to automatically set time when device is inserted into USB port. See example [here](https://raw.githubusercontent.com/trustcrypto/trustcrypto.github.io/master/49-onlykey.rules)


**Scripted provisioning of an OnlyKey slots and keys can be done by creating a script that sets multiple values on OnlyKey**

### List and Remove FIDO2 Resident Key

List current resident keys:

```
onlykey-cli credential ls
```
![](https://raw.githubusercontent.com/trustcrypto/trustcrypto.github.io/master/images/cli-cred-ls.png)

Remove a resident key by credential ID

```
onlykey-cli credential rm eu7LPIjTNwIJt2Ws9LWJlXkiNKaueSEEGteZM2MT/lZtEuYo49V6deCiIRMb6EDC29XG13nBL60+Yx+6hxSUYS1uxX9+AA==
```

Once removed, list current resident keys to verify:

![](https://raw.githubusercontent.com/trustcrypto/trustcrypto.github.io/master/images/cli-cred-ls2.png)

## Source

[OnlyKey CLI on Github](https://github.com/trustcrypto/python-onlykey)

## Third-party code

`onlykey/openpgp_bridge/openpgp.js` is [OpenPGP.js](https://openpgpjs.org) v6, licensed under the GNU LGPL v3. `loadpqc` runs it (through Node.js) to read composite PQC PGP key files.
