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

    file = open(library, 'rb')
    enc = file.read()
    file.close()
    hash = open('hash', 'r', newline='').read()
    password = getpass.getpass('Master password: ')
    if hash == calculateHash(password):

        raw = (decode(enc, calculateHashBin(password)))
        try:
            type = int(input('Mode:\n(1) List all passwords\n(2) Find By Username\n(3) Find By Name\n'))
            if (type == 2) or (type == 3):
                search = input('Search term: ').lower()
            print()
        except Exception as e:
            print('\nInvalid Type!\nExiting...\n', file=sys.stderr)
            sys.exit()
        if type == 1:
            print(raw+'\n')
        elif type == 2:
            raw = raw.split('\n')
            for line in raw:
                if line[0] != ' ':
                    last = line
                if (search in line) and (line[0]==' '):
                    if last:
                        print(last)
                        last = ''
                    print(line)
            print()
        elif type == 3:
            raw = raw.split('\n')
            for i in range(len(raw)):
                if (search in raw[i].lower()) and (raw[i][0]!=' '):
                    print(raw[i])
                    try:
                        while raw[i+1][0]==' ':
                            print(raw[i+1])
                            i += 1
                    except:
                        pass
            print()

        else:
            print('\nInvalid Type!\nExiting...\n', file=sys.stderr)
            sys.exit()

        del raw
    else:
        print('\nWrong password!\nExiting...\n', file=sys.stderr)
        sys.exit()
    del password
except Exception as e:
    print('\nLibrary not found!\nExiting...\n', file=sys.stderr)
    sys.exit()
