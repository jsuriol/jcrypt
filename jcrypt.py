#!/usr/bin/env python
'''
  jcrypt 1.0

  Toy encryption program.

  Usage: jcrypt.py <file>           #  Encrypt <file>.
         jcrypt.py <jcrypt_file>    #  Decrypt  <jcrypt_file>.
         jcrypt.py -d <file>        #  Print debugging information during encrypting/decrypting.
         jcrypt.py -i <jcrypt_file  #  Print information about <jcrypt_file>.
         jcrypt.py -p               #  Generate a password of default length (10).
         jcrypt.py -p <length>      #  Generate a password of <length> length (range 10-1024).

  The <file> argument is deemed a stream of bytes, whether it's a text file or a binary file.

  jcrypt encrypts <file> and creates <file>.jcrypt.

  If <file> is a jcrypt file, regarless of file name extension, jcrypt decrypts it and
  creates <file>.jclear.

  If <file> name contains periods, jcrypt uses the name up to and excluding the
  first period. For example if the input file name is 'foobar.new.txt' the
  output file will be 'foobar.jclear' with the cleartext.

  The maximum input file size is MAXCLEARSIZE.

  Encrypting method:

   1. Modify the password (key) with salt_key().
   2. Modify cleartext (clear_bytes) with a one-time pad of random numbers of equal length (mask).
   3. Generate a padding of random numbers of random length (excess).
   4  Concatenate modified cleartext, one-time pad, and excess pad, into basic ciphertext.
   5. Augment basic ciphertext by inserting the length of the cleartext at a location derived from the key length.
   6. Modify the augmented ciphertext with the key for the final ciphertext.
   7. Write header and final ciphertext to file.

   The header contains: name: "jcrypt," version, date, file type, ciphertext digest, cleartest digest and key digest.

'''
import os
import sys
import time
import array
import string
import getpass
import hashlib
import secrets
import argparse
import statistics
from datetime import datetime

#
#  Constants.
#
PROG    = 'jcrypt'
VERSION = '1.0'
CODE    = 'utf8'
ORDER   = 'little'
XORMASK = 0b01101001
MAGIC   = 0xfe0cf0c0
MINKEY  = 10
MAXKEY  = 1024
ENCRYPT = 1
DECRYPT = 2
ESUFFIX = '.' + PROG
DSUFFIX = '.jclear'
SHA256  = hashlib.sha256
SHA512  = hashlib.sha512

#
#  Header and header fields lengths.
#
VERSION_FIELD = f'{VERSION:>8}'
MAGIC_LEN     = 4
NAME_LEN      = len(PROG.encode(CODE))
VERSION_LEN   = len(VERSION_FIELD)
TIME_LEN      = 4
SHA256_LEN    = 64
SHA512_LEN    = 128
HEADER_LEN    = MAGIC_LEN + NAME_LEN + VERSION_LEN + TIME_LEN + SHA256_LEN * 3

#
#  Size in bytes of the biggest chunk to encrypt.
#
MAXCHUNKSIZE = 1000000    
#
#  Size in bytes of the biggest file accepted. 
#
MAXFILESIZE  = 50000000
MINCLEARSIZE = 15
MAXCLEARSIZE = MAXFILESIZE // 3

# For key generator.
KEY_MIN_LEN  = 10
KEY_MAX_LEN  = 1024

CIPHER_CHECKSUM = 1
CLEAR_CHECKSUM  = 2
KEY_CHECKSUM    = 3

MAX_DEBUG_LEN = 250

#
#  Global variable.
#
DEBUG = False

def log(s):
    if DEBUG and len(s) < MAX_DEBUG_LEN:
        print(s)

def get_info(data):
    '''
        Extract header and header fields.
        header_bytes = data[:HEADER_LEN]
        :param data: input file bytes.
    '''
    header = data[:HEADER_LEN]
    begin = 0
    end   = MAGIC_LEN
    magic_bytes  = header[begin:end]
    magic = int.from_bytes(magic_bytes, byteorder=ORDER)

    begin += MAGIC_LEN
    end   += NAME_LEN
    name_bytes = header[begin:end]
    name = name_bytes.decode(CODE)

    if magic != MAGIC or name != PROG:
        return None

    begin += NAME_LEN
    end   += VERSION_LEN
    version_bytes = header[begin:end]
    version = version_bytes.decode(CODE).strip()

    begin += VERSION_LEN
    end   += TIME_LEN
    time_bytes = header[begin:end]
    time = int.from_bytes(time_bytes, byteorder=ORDER)

    log(f'get_info: {name} {version} {time}')

    return (name, version, time)


def get_header_checksum(data, which):
    '''
        Extract a checksum from the header.
        :param data: jcrypt input file.
        :param which: which checksum.
        :return: requested checsum or None.
    '''
    header = data[:HEADER_LEN]
    l = SHA256_LEN
    ck = header[-l*3:]  #  Header checksums section.
    if which == CIPHER_CHECKSUM:
        return ck[:l]
    elif which == CLEAR_CHECKSUM:
        return ck[l:l*2]
    elif which == KEY_CHECKSUM:
        return ck[-l:]
    else:
        return None


def print_info(filename):
    '''
        Print header information.
        :param filename: jcrypt file name.
    '''
    with open(filename, "rb") as fp:
        data = fp.read()  #  Read input file as bytes.
    info = get_info(data)
    if not info:
        print(f'ERROR: not a valid jcrypt file')
        return
    name, version, time = info
    print('\n')
    print(f'Information for file {filename}:')
    print(f'    Name:    {name}')
    print(f'    Version: {version.strip()}')
    print(f"    Date:    {datetime.utcfromtimestamp(time).strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print('\n')


def validate(data):
    '''
        Returns the operation to perform according to
        whether the input file is a valid jcript file or not.
        :param data: bytes from input file.
        :return: ENCRIPT, DECRIPT, or None if error.

    '''
    info = get_info(data)

    if not info:
        #
        #  Not a jcrypt file.
        #
        return (ENCRYPT)

    name, version, time = info

    log(f'validate: name: {name}')

    log(f'validate: version: {version}')

    if version != VERSION:
        print('ERROR: Wrong program version, expected {VERSION}, is {version}')
        return None

    cipher_checksum = get_checksum(data[HEADER_LEN:])
    header_cipher_checksum = get_header_checksum(data, CIPHER_CHECKSUM)

    log(f'validate: current cipher ckecksum: {cipher_checksum}')
    log(f'validate: header cipher checksum:  {header_cipher_checksum}')

    if cipher_checksum != header_cipher_checksum:
        print('ERROR: Bad ciphertext checksum')
        return None

    return DECRYPT


def write_crypt(cipher, clear, key_bytes, filename):
    '''
        Write header and payload to file
        :param cipher: encrypted payload.
        :param clear: original cleartext.
        :param key_bytes: secret key.
        :param filename: input file name.
    '''
    #
    #  Build header and write header and payload.
    #  Header consists of a magic number, program name,
    #  version, timestamp, ciphertext checksum,
    #  cleartext checksum, and key checksum.
    #
    magic_bytes   = MAGIC.to_bytes(4, byteorder=ORDER)
    name_bytes    = PROG.encode(CODE)
    version_bytes = VERSION_FIELD.encode(CODE)
    utctime       = int(time.time())
    time_bytes    = utctime.to_bytes(4, byteorder=ORDER)
    cipher_cksum  = get_checksum(cipher)
    clear_cksum   = get_checksum(clear)
    key_cksum     = get_checksum(key_bytes)
    header        = (magic_bytes + name_bytes + version_bytes + time_bytes +
                     cipher_cksum + clear_cksum + key_cksum)

    assert(len(header) == HEADER_LEN)

    log(f'write_crypt: key_bytes: {key_bytes}')
    log(f'write_crypt: key_bytes  {[bt for bt in key_bytes]}')
    log(f'write_crypt: cipher checksum: {cipher_cksum}')
    log(f'write_crypt: cipher checksum   {[bt for bt in cipher_cksum]}')
    log(f'write_crypt: clear checksum:  {clear_cksum}')
    log(f'write_crypt: clear checksum  {[bt for bt in clear_cksum]}')
    log(f'write_crypt: key checksum:    {key_cksum}')
    log(f'write_crypt: key checksum  {[bt for bt in key_cksum]}')

    newfilename = os.path.basename(filename).split('.')[0] + ESUFFIX

    log(f'write_crypt: newfilename: {newfilename}')

    try:
        with open(newfilename, "wb") as fp:
            fp.write(header)
            fp.write(cipher)
    except OSError as e:
        print(f'ERROR I/O error {e.strerror}')

    print(f'\nEncrypted file name: {newfilename}\n')


def write_clear(cleartext, filename):
    '''
        Write cleartext to file.
        :param cleartext: cleartext.
        :param filename: output file name.
    '''
    newfilename = os.path.basename(filename).split('.')[0] + DSUFFIX

    log(f'write_clear: newfilename: {newfilename}')

    try:
        with open(newfilename, "wb") as fp:
            fp.write(cleartext)
    except OSError as e:
        print(f'ERROR I/O error {e.strerror}')

    print(f'\nDecrypted file name: {newfilename}')


def get_key():
    '''
        Get the password (henceforth known as 'key').
    '''
    print('Getting the key')
    while True:
        try:
            key = getpass.getpass()
        except Exception as error:
            print(f'ERROR: {error}')
        key_len = len(key)
        log(f'get_key: key: {key}')
        if key_len < MINKEY or key_len > MAXKEY:
            print(f'ERROR: password must be between {MINKEY}-{MAXKEY} characters long')
        else:
            break
    return key


def get_checksum(data_bytes, sha=SHA256):
    '''
        Get a sha digest of the data_bytes.
        :param data: data to checksum.
        :param she: kind of sha digest to calculate.
        :return: hexdigest string byte encoded.
    '''
    digest = sha(data_bytes).hexdigest().encode(CODE)

    log(f'get_checksum: data_bytes: {data_bytes}')
    log(f'get_checksum: data_bytes: {[bt for bt in data_bytes]}')
    log(f'get_checksum: digest: {digest}')
    log(f'get_checksum: digest: {[bt for bt in digest]}')

    return digest


def salt_key(key_bytes):
    '''
        Salt the key bytes.
        if key is < SHA512_LEN use its sha512 digest as key.
        if key is > SHA512_LEN XOR with its sha512 digest.
        Finally XOR with XORMASK rotated for each successive byte.
        :param key_bytes: byte array to salt.
        :return: salted byte array.
    '''
    def rotate(byte, bits):
        '''
            :param byte: integer to rotate
            :bits, bits: number of bits to rotate.
            :return: rotated integer.
        '''
        if isinstance(byte, int):
            b = bin(byte)[2:].zfill(8)
        else:
            b = byte
        return int(b[-bits:] + b[:-bits], 2)

    log(f'salt_key: key_bytes A: {[key_bytes]}')
    log(f'salt_key: key_bytes A: {[bt for bt in key_bytes]}')

    key_sha512 = get_checksum(key_bytes, SHA512)

    if len(key_bytes) > SHA512_LEN:
        salted_key = bytearray(key_bytes)
        i = 0
        for bt in key_bytes:
            mask = key_sha512[i % SHA512_LEN]
            salted_key[i] ^= mask
            i += 1
    else:
        salted_key = bytearray(key_sha512)

    log(f'salt_key: salted_key: B {[salted_key]}')
    log(f'salt_key: salted_key: B {[bt for bt in salted_key]}')

    log(f'salt_key: plain salted_key mean:  {statistics.mean(list(salted_key)):.2f}')
    log(f'salt_key: plain salted_key stdev: {statistics.stdev(list(salted_key)):.2f}')

    mask = XORMASK
    i = 0
    #
    #  This step ~triples the standard deviation of the salted_key.
    #
    for bt in salted_key:
        salted_key[i] ^= mask
        mask = rotate(mask, 1)
        i += 1

    log(f'salt_key: masked salted_key mean:  {statistics.mean(list(salted_key)):.2f}')
    log(f'salt_key: masked salted_key stdev: {statistics.stdev(salted_key):.2f}')

    log(f'salt_key: salted_key: C {[salted_key]}')
    log(f'salt_key: salted_key: C {[bt for bt in salted_key]}')

    return bytes(salted_key)


def encrypt(key, data, filename):
    '''
        Encrypt cleartext using key.
        :param key: key string.
        :param data: cleartext bytes.
        :return: 0 for success 1 for error.
    '''
    l = len(data)
    if l < MINCLEARSIZE or l > MAXCLEARSIZE:
        print(f'Input file size must be between {MINCLEARSIZE} and {MAXCLEARSIZE}')
        return 1

    key_bytes = key.encode(CODE)
    key_len = len(key_bytes)
    clear_bytes = bytearray(data)
    clear_len = len(clear_bytes)
    clearlen_bytes = clear_len.to_bytes(4, byteorder=ORDER)

    log(f'encrypt: key_len: {key_len}')
    log(f'encrypt: key_bytes: {key_bytes}')
    log(f'encrypt: key_bytes: {[b for b in key_bytes]}')
    log(f'encrypt: clear_len: {clear_len}')
    log(f'encrypt: clear_bytes: {clear_bytes}')
    log(f'encrypt: clear_bytes: {[b for b in clear_bytes]}')

    salted_key = salt_key(key_bytes)

    log(f'encrypt: salted_key len: {len(salted_key)}')

    #
    #  One-time pad, to mask cleartext.
    #
    mask = bytes(secrets.token_bytes(clear_len))

    log(f'encrypt: mask bytes: {mask}')
    log(f'encrypt: mask bytes: {[b for b in mask]}')

    reverse_mask = mask[::-1]

    log(f'encrypt: reverse mask_bytes: {reverse_mask}')
    log(f'encrypt: reverse mask_bytes: {[b for b in reverse_mask]}')

    #
    #  Mask clear_bytes.
    #
    masked_clear_bytes = bytes(b ^ m for b, m in zip(clear_bytes, mask))

    log(f'encrypt: masked clear bytes: {masked_clear_bytes}')
    log(f'encrypt: masked clear bytes: {[b for b in masked_clear_bytes]}')

    #
    #  If key is longer than cleartext+mask, add padding to ciphertext
    #  to make it longer than the key.
    #
    if key_len > clear_len * 2:
        pad = secrets.token_bytes(key_len - clear_len * 2 + 7)
    else:
        #
        #  Add a random length of garbage random bytes to the cipher,
        #  of maximum length proportional to clear_len.
        #
        pad_max_len = clear_len // 4 + 4
        pad_min_len = 3
        pad = secrets.token_bytes(secrets.choice(range(pad_min_len, pad_max_len)))
        log(f'encrypt: pad_max_len: {pad_max_len}')

    log(f'pad_len: {len(pad)}')

    #
    #  Join masked cleartext, reverse mask and padding.
    #
    cipher = masked_clear_bytes + reverse_mask + pad

    log(f'encrypt: cipher len: {len(cipher)}')
    log(f'encrypt: cipher: {cipher}')
    log(f'encrypt: cipher: {[b for b in cipher]}')

    #
    #  Insert the cleartext length at the point given by the key length.
    #
    part1 = cipher[:key_len]
    part2 = cipher[key_len:]
    cipher2 = bytearray(part1 + clearlen_bytes + part2)

    log(f'encrypt: part1 len: {len(part1)}')
    log(f'encrypt: part1: {part1}')
    log(f'encrypt: part1: {[b for b in part1]}')
    log(f'encrypt: clearlen bytes: {clearlen_bytes}')
    log(f'encrypt: clearlen bytes: {[b for b in clearlen_bytes]}')
    log(f'encrypt: part2 len: {len(part2)}')
    log(f'encrypt: part2: {part2}')
    log(f'encrypt: part2: {[b for b in part2]}')
    log(f'encrypt: cipher2 len: {len(cipher2)}')
    log(f'encrypt: cipher2: {cipher2}')
    log(f'encrypt: cipher2: {[b for b in cipher2]}')

    #
    #  XOR with salted key.
    #
    i = 0
    l = len(salted_key)
    for bt in cipher2:
        mask = salted_key[i % l]
        cipher2[i] = bt ^ mask
        i += 1

    log(f'encrypt: cipher final: {cipher2}')
    log(f'encrypt: cipher final: {[b for b in cipher2]}')
    log(f'encrypt: cipher final mean:   {statistics.mean(list(salted_key)):.2f}')
    log(f'encrypt: cipher final stdev:  {statistics.stdev(cipher2):.2f}')

    write_crypt(cipher2, data, key_bytes, filename)

    return 0


def decrypt(key, data, filename):
    '''
        Decrypt ciphertext.
        If key checksum doesn't match header key
        checksum abort.
        if cleartext checksum equals the header cleartext
        checksum decryption succeeds else fails.
        :param key: key string.
        :param data: ciphertext bytes.
        :param filename: ciphertext file.
        :return: 0 for success 1 for error.
    '''
    cipher = bytearray(data[HEADER_LEN:])

    log(f'decrypt: cipher {cipher}')
    log(f'decrypt: cipher: {[b for b in cipher]}')

    #
    #  Check the checksum of the given key is
    #  equal to the header key ckecksum.
    #
    key_bytes = key.encode(CODE)
    key_checksum = get_checksum(key_bytes)
    header_key_checksum = get_header_checksum(data, KEY_CHECKSUM)

    log(f'decrypt: key_bytes: {key_bytes}')
    log(f'decrypt: key_bytes: {[b for b in key_bytes]}')
    log(f'decrypt: current key checksum: {key_checksum}')
    log(f'decrypt: header key checksum:  {header_key_checksum}')

    if key_checksum != header_key_checksum:
        print(f'Decryption of file: {filename} failed')
        return 1

    key_len = len(key_bytes)
    salted_key = salt_key(key_bytes)

    #
    #  XOR ciphertext with salted key.
    #
    i = 0
    l = len(salted_key)
    for bt in cipher:
        mask = salted_key[i % l]
        cipher[i] = bt ^ mask
        i += 1

    log(f'decrypt: cipher2: {cipher}')
    log(f'decrypt: cipher2: {[b for b in cipher]}')

    #
    #  Extract length of clear_bytes.
    #
    clearlen_bytes = cipher[key_len:key_len+4]

    log(f'decrypt: clearlen_bytes: {clearlen_bytes}')

    clear_len = int.from_bytes(clearlen_bytes, byteorder=ORDER)

    log(f'decrypt: clear_len: {clear_len}')

    #
    #  Extract clear_bytes and mask.
    #
    del cipher[key_len:key_len+4]  #  Delete clearlen_bytes.
    masked_clear_bytes = cipher[:clear_len]
    reverse_mask = cipher[clear_len:clear_len*2]
    mask = reverse_mask[::-1]

    log(f'decrypt: masked clear_bytes: {masked_clear_bytes}')
    log(f'decrypt: masked clear_bytes: {[b for b in masked_clear_bytes]}')
    log(f'decrypt: mask: {mask}')
    log(f'decrypt: mask: {[b for b in mask]}')

    #
    #  Unmask clear_bytes.
    #
    clear_bytes = bytes(b ^ m for b, m in zip(masked_clear_bytes, mask))

    log(f'decrypt: clear_bytes: {clear_bytes}')
    log(f'decrypt: clear_bytes: {[b for b in clear_bytes]}')

    #
    #  Compare the checksum of the clear_bytes
    #  with the the header clear checksum.
    #
    clear_bytes_checksum = get_checksum(clear_bytes)
    header_clear_checksum = get_header_checksum(data, CLEAR_CHECKSUM)

    log(f'decrypt: clear_checksum:        {clear_bytes_checksum}')
    log(f'decrypt: header clear checksum: {header_clear_checksum}')

    if clear_bytes_checksum != header_clear_checksum:
        print(f'Decryption of file: {filename} failed')
        return 1

    try:
        clear = clear_bytes.decode(CODE)
        log(f'decrypt: clear: {clear}')
    except UnicodeDecodeError:
        pass

    write_clear(clear_bytes, filename)

    return 0


def key_gen(n):
     '''
         Generate a random password.
         :param: password length.
         :return: password.
     '''
     if n < KEY_MIN_LEN or n > KEY_MAX_LEN:
         print(f'ERROR: length of password requested must be in the range {KEY_MIN_LEN} and {KEY_MAX_LEN}')
         return None
     punct = '!#$%&*?@'
     char_set = string.ascii_letters + string.digits + punct
     while True:
         key = ''.join(secrets.choice(char_set) for i in range(n))
         if (any(c.islower() for c in key)
             and any(c in punct for c in key)
             and any(c.isupper() for c in key)
             and sum(c.isdigit() for c in key) >= 3):
             break
     return key


def main():

    global DEBUG

    print('\nSTART')
    password_help = '''Generate a password, for a given length, maximum length: 1024, minimum: 10, default: 10.'''
    version = PROG + ' ' + VERSION

    parser = argparse.ArgumentParser(prog='jcrypt', description='Encryption tool.')
    parser.add_argument('-d', '--debug', action='store_true', default=False, help="Turn on debugging.")
    parser.add_argument('-i', '--info', action='store_true', help="show file header information")
    parser.add_argument('-p', '--password', nargs='?', type=int, metavar='length', const=KEY_MIN_LEN, help=password_help)
    parser.add_argument('-v', '--version', action='version', version=version)
    parser.add_argument('datafile', nargs='?', metavar='input_file')
    args = parser.parse_args()

    nargs = len(sys.argv)
    if nargs == 1 or nargs == 2 and args.debug:
        parser.error('Input file required.')
        parser.print_help()
        return 1

    if args.debug:
        DEBUG = True

    if args.info:
        if args.datafile:
            print_info(args.datafile)
        else:
            parser.print_help()
            return 1
        return 0

    if args.password:
        key = key_gen(args.password)
        if key:
            print(f'\nGenerated password: {key}')
            print(f'\nPassword length: {len(key)}\n')
        else:
            return 1
        return 0

    if args.datafile:
        filename = args.datafile
        try:
            print("Before getsize.")
            size = os.path.getsize(filename)
            if MINCLEARSIZE > size > MAXFILESIZE:
                print("Valid input file size range is {MINCLEARSIZE}-{MAXFILESIZE}")
                return 1
            with open(filename, "rb") as fp:
                data = fp.read()  #  Read input file as bytes.
        except OSError as e:
             print(f'ERROR I/O error {e.strerror}')
             return 1

        status = validate(data)
        if not status:
            print("ERROR: Invalid input file data")
            return 1

        key = get_key()

        if status == ENCRYPT:
            print('DEBUG: encripting...')
            retval = encrypt(key, data, filename)
        elif status == DECRYPT:
            print('DEBUG: decripting...')
            retval = decrypt(key, data, filename)

    return retval

if __name__ == "__main__":
    try:
        sys.exit(main())
    except(KeyboardInterrupt):
        print('\n...Program Stopped Manually!')
        raise




'''
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Pseudo-random key and initialisation vector
key = os.urandom(32)           # (32*8=256-bit. AES also accepts 128/192-bit)
init_vector = os.urandom(16)   # (16*8=128-bit. AES only accepts this size)

# Setup module-specific classes
cipher = Cipher(algorithms.AES(key), modes.CBC(init_vector))
encryptor = cipher.encryptor()
decryptor = cipher.decryptor()

# Encrypt and decrypt data
cyphertext = encryptor.update(b"a secret message") + encryptor.finalize()
plaintext = decryptor.update(cyphertext) + decryptor.finalize()
print(plaintext) # 'a secret message'
'''
