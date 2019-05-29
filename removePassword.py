#!/usr/bin/python3

import sys
import hashlib
import getpass
from Crypto.Cipher import AES
from Crypto import Random
import base64


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


masterPassword = getpass.getpass('Master password: ')

file = open('hash', 'r', newline='')
hash = file.read()
file.close()

if calculateHash(masterPassword) !=  hash:
    print('\nWrong password!\nExiting...\n', file=sys.stderr)
    sys.exit()

try:
    type = int(input('\n(1) By Username\n(2) By Name\n').strip())
    if type != 1 and type != 2:
        raise Exception
except Exception as e:
    print('\nInvalid type!\nExiting...\n', file=sys.stderr)
    sys.exit()

if type == 1:
    username = input('Username: ').strip()
name = input('Name: ').strip()


deleteitemp = False

file = open(library, 'rb')
enc = file.read()
file.close()

raw = decode(enc, calculateHashBin(masterPassword)).split('\n')

deleted = 0

for i in range(len(raw)):
    if name.lower() + ':' == raw[i].lower():
        if type == 1:
            itemp = i
            try:
                if raw[i+2][0] != ' ':
                    deleteitemp = True
            except:
                deleteitemp = True
            try:
                while raw[i+1][0] == ' ':
                    if raw[i+1][4:4+len(username)].lower() == username.lower():
                        del raw[i+1]
                        deleted += 1
                        break
                    i += 1
                break
            except:
                print('Password not found!')
        elif type == 2:
            del raw[i]
            try:
                while raw[i][0]==' ':
                    del raw[i]
                    deleted += 1
                break
            except:
                break
if deleteitemp:
    del raw[itemp]
if deleted == 0:
    print('Password not found!')
else:
    print(str(deleted) + ' password(s) removed!')

raw = '\n'.join(raw)

file = open(library, 'wb')
file.write(encode(raw, calculateHashBin(masterPassword)))
file.close
del raw
del masterPassword
