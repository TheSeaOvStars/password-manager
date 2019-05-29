#!/usr/bin/python3

import hashlib
import getpass
from Crypto.Cipher import AES
from Crypto import Random
import base64
import sys


library = 'passwords'

BS = AES.block_size
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s: s[0:-ord(s[-1])]

def calculateHash(password):
    crypt = hashlib.sha3_512()
    crypt.update(password.encode('utf-8'))
    return crypt.hexdigest()

def calculateHashBin(password):
    crypt = hashlib.sha3_256()
    crypt.update(password.encode('utf-8'))
    return crypt.digest()

def encode(raw, key):
    raw = pad(raw)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(raw))

def decode(encoded, key):
    encoded = base64.b64decode(encoded)
    iv = encoded[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(encoded[AES.block_size:]).decode('utf-8'))


try:
    found = False

    file = open('hash', mode='r', newline='')
    found = True
    hash = file.read()
    file.close()
    oldPassword = getpass.getpass('Old master password to keep your passwords: ')
    if hash == calculateHash(oldPassword):
        newPassword = getpass.getpass('New master password: ')
        file = open('hash', mode='w', newline='')
        file.write(calculateHash(newPassword))
        file.close()

        file = open(library, mode='rb')
        enc = file.read()
        file.close()
        raw = decode(enc, calculateHashBin(oldPassword))
        newEnc = encode(raw, calculateHashBin(newPassword))
        file = open(library, mode='wb')
        file.write(newEnc)
        file.close()

        del raw
        del newPassword
    else:
        print('\nPasswords not matching!\nExiting...\n', file=sys.stderr)
except:
    if found == False:
        newPassword = getpass.getpass('Enter master password for new database: ')
        file = open('hash', mode='w', newline='')
        file.write(calculateHash(newPassword))
        file.close()
        try:
            file = open(library, 'r', newline='')
            raw = file.read()
            file.close()
            file = open(library, 'wb')
            file.write(encode(raw, calculateHashBin(newPassword)))
            file.close()
            del raw
        except:
            file = open(library, 'wb')
            file.write(encode('', calculateHashBin(newPassword)))
            file.close()

        del newPassword
