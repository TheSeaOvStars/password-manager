#!/usr/bin/python3

import string
import secrets
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

characters = string.ascii_letters + string.punctuation + string.digits


masterPassword = getpass.getpass('Master password: ')

file = open('hash', 'r', newline='')
hash = file.read()
file.close()

if calculateHash(masterPassword) !=  hash:
    print('\nWrong password!\nExiting...\n', file=sys.stderr)
    sys.exit()

name = input('Name: ').strip()
username = input('Username: ').strip()
if username.lower() == 'random' or username.lower() == 'r':
    try:
        usernameLength = int(input('Max username length: ').strip())
    except Exception as e:
        print('\nLength must be a number!\nExiting...\n', file=sys.stderr)
        sys.exit()
else:
    usernameLength = 100
try:
    type = int(input('Type?:\n(1) Random\n(2) Diceware\n(3) Custom Password\n').strip())
except Exception as e:
    print('\nInvalid type!\nExiting...\n', file=sys.stderr)
    sys.exit()

if type != 3:
    try:
        passwordLength = int(input('Length: '))
    except Exception as e:
        print('\nLength must be a number!\nExiting...\n', file=sys.stderr)
        sys.exit()

wordsFile = 'words'


randomGenerator = secrets.SystemRandom()

if username == '':
    username = 'none'
if username.lower() == 'random' or username.lower() == 'r':
    try:
        file = open(wordsFile, 'r')
        words = file.read().split()
        cnt = 0
        while True:
            cnt += 1
            username = ''.join(randomGenerator.choice(words).title() for i in range(2))
            if (len(username) <= usernameLength) or (cnt == 1000000):
                break
        if cnt == 1000000:
            print('Length too short, trying single-word name')
            cnt = 0
            while True:
                cnt += 1
                username = randomGenerator.choice(words).title()
                if (len(username) <= usernameLength) or (cnt == 1000000):
                    break
        if cnt == 1000000:
            print('\nUsername length too short!\nExiting...\n', file=sys.stderr)
            sys.exit()
        file.close()
    except Exception as e:
        print('\nFile "words" not found!\nExiting...\n', file=sys.stderr)
        print(e)
        sys.exit()


if type == 1:
    password = ''.join(randomGenerator.choice(characters) for i in range(passwordLength))
elif type == 2:
    try:
        file = open(wordsFile, 'r')
        words = file.read().split()
        password = ''.join(randomGenerator.choice(words).lower() + ' ' for i in range(passwordLength))
    except Exception as e:
        print('\nFile "words" not found!\nExiting...\n', file=sys.stderr)
        sys.exit()
elif type == 3:
    password = getpass.getpass('Password: ')
else:
    print('\nInvalid Type!\nExiting...\n', file=sys.stderr)
    sys.exit()



found = False;

file = open(library, 'rb')
enc = file.read()
file.close()

raw = decode(enc, calculateHashBin(masterPassword)).split('\n')

if raw[-1] == '':
    del raw[-1]
for i in range(len(raw)):
    if name.lower() + ':' == raw[i].lower():
        raw.insert(i+1, f'    {username}: {password}')
        found = True;
if not found:
    raw.append(f'{name}:')
    raw.append(f'    {username}: {password}')

raw = '\n'.join(raw)

file = open(library, 'wb')
file.write(encode(raw, calculateHashBin(masterPassword)))
file.close
del raw
del masterPassword
