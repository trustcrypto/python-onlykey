# coding: utf-8
import hashlib
import time
import os

from binascii import hexlify
import pyelliptic

from onlykey import OnlyKey, Message

print('Generating a new NIST P-256 key pair...')

# Asymmetric encryption
alice = pyelliptic.ECC(curve='prime256v1')
bob = pyelliptic.ECC(curve='prime256v1')

bob_private_key = bob.get_privkey()
alice_public_key = alice.get_pubkey()
bob_public_key = bob.get_pubkey()
alice_private_key = alice.get_privkey()

print("Bob's private key: ", hexlify(bob_private_key))
print("Bob's public key: ", hexlify(bob_public_key))

print()
print("Alices's private key: ", hexlify(alice_private_key))
print("Alices's public key: ", hexlify(alice_public_key))
print()

print()
print('Initialize OnlyKey client...')
ok = OnlyKey()
print('Done')
print()

time.sleep(2)

ok.read_string(timeout_ms=100)
empty = 'a'
while not empty:
    empty = ok.read_string(timeout_ms=100)

print('You should see your OnlyKey blink 3 times')
print()

print('Setting ECC private...')
ok.set_ecc_key(101, (2+32), bob_private_key)
# Slot 101 - 132 for ECC
# Type 1 = Ed25519, Type 2 = p256r1, Type 3 = p256k1
# Key Features -
# if backup key = type + 128
# if signature key = type + 64
# if decryption key = type + 32
# if authentication key = type + 16
# For this example it will be a decryption key
time.sleep(1.5)
print(ok.read_string())

time.sleep(2)
print('You should see your OnlyKey blink 3 times')
print()


payload = alice_public_key

#We are simulating message here, according to refernce below it is a known value to both parties - unsigned char message[256];

#
#    // Reference - https://www.ietf.org/mail-archive/web/openpgp/current/msg00637.html
#	// https://fossies.org/linux/misc/gnupg-2.1.17.tar.gz/gnupg-2.1.17/g10/ecdh.c
#	// gcry_md_write(h, "\x00\x00\x00\x01", 4);      /* counter = 1 */
#    // gcry_md_write(h, secret_x, secret_x_size);    /* x of the point X */
#    // gcry_md_write(h, message, message_size);      /* KDF parameters */
#	// This is a limitation as we have to be able to fit the entire message to decrypt
#	// In this way RSA seems to have an advantage?
#	// /* Build kdf_params.  */
#    //{
#    //IOBUF obuf;
#    //
#    //obuf = iobuf_temp();
#    ///* variable-length field 1, curve name OID */
#    //err = gpg_mpi_write_nohdr (obuf, pkey[0]);
#    ///* fixed-length field 2 */
#    //iobuf_put (obuf, PUBKEY_ALGO_ECDH);
#    ///* variable-length field 3, KDF params */
#    //err = (err ? err : gpg_mpi_write_nohdr (obuf, pkey[2]));
#    ///* fixed-length field 4 */
#    //iobuf_write (obuf, "Anonymous Sender    ", 20);
#    ///* fixed-length field 5, recipient fp */
#    //iobuf_write (obuf, pk_fp, 20);
#
#
#


print('Payload containing ephemeral public key', repr(payload))
print()

# Compute the challenge pin
h = hashlib.sha256()
h.update(payload)
d = h.digest()

assert len(d) == 32

def get_button(byte):
    ibyte = ord(byte)
    if ibyte < 6:
        return 1
    return ibyte % 5 + 1

b1, b2, b3 = get_button(d[0]), get_button(d[15]), get_button(d[31])

print('Sending the payload to the OnlyKey...')
ok.send_large_message2(msg=Message.OKDECRYPT, payload=payload, slot_id=101)

# Tim - The OnlyKey can send the code to enter but it would be better if the app generates
# the code, this way in order to trick a user into approving an unauthorized signature
# the app, in this case this python code would have to be hacked on the user's system.
# How the OnlyKey creates the three digit code:
# SHA256_CTX CRYPTO;
# sha256_init(&CRYPTO);
# sha256_update(&CRYPTO, large_buffer, large_data_offset); //step 1 create a sha256 hash of
# sha256_final(&CRYPTO, rsa_signature); //the data to sign
# if (rsa_signature[0] < 6) Challenge_button1 = '1'; //step 2 Convert first byte of hash to
# else { //first button to press (remainder of byte is a base 6 number 0 - 5)
# Challenge_button1 = rsa_signature[0] % 5;
# Challenge_button1 = Challenge_button1 + '0' + 1; //Add '0' and 1 so number will be ASCII 1 - 6
# }
# if (rsa_signature[15] < 6) Challenge_button2 = '1'; //step 3 do the same with 16th byte to
# else { // get Challenge_button2
# Challenge_button2 = rsa_signature[15] % 5;
# Challenge_button2 = Challenge_button2 + '0' + 1;
#}
# if (rsa_signature[31] < 6) Challenge_button3 = '1'; //step 4 do the same with 32nd byte to
# else { // get Challenge_button
# Challenge_button3 = rsa_signature[31] % 5;
# Challenge_button3 = Challenge_button3 + '0' + 1;
# }
# step 5 display the code to user to enter on OnlyKey

# This method prevents some malware on a users system from sending fake requests to be signed
# at the same time as real requests and tricking the user into signing the wrong data
print('Please enter the 3 digit challenge code on OnlyKey (and press ENTER if necessary)')
print('{} {} {}'.format(b1, b2, b3))
raw_input()
shared_secret1 = alice.get_ecdh_key(bob.get_pubkey())
shared_secret2 = bob.get_ecdh_key(alice.get_pubkey())
print('Trying to read the shared secret from OnlyKey...')
ok_shared_secret = ''
while ok_shared_secret == '':
    time.sleep(0.5)
    ok_shared_secret = ok.read_bytes(len(shared_secret1), to_bytes=True)

print('OnlyKey Shared Secret =', hexlify(ok_shared_secret))

print('Local Shared Secret1 =', hexlify(shared_secret1))
print()

print('Local Shared Secret2 =', hexlify(shared_secret2))
print()

print('Assert that both shared secrets match')
print((hexlify(alice.get_ecdh_key(bob.get_pubkey()))))
assert repr(shared_secret1) == repr(ok_shared_secret)
print('Ok, secrets match')
print()


print('Done')
