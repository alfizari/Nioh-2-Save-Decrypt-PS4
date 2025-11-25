#!/usr/bin/env python3
"""
This is an exercise in secure symmetric-key encryption, implemented in pure
Python (no external libraries needed).

Original AES-128 implementation by Bo Zhu (http://about.bozhu.me) at 
https://github.com/bozhu/AES-Python . PKCS#7 padding, CBC mode, PKBDF2, HMAC,
byte array and string support added by me at https://github.com/boppreh/aes. 
Other block modes contributed by @righthandabacus.


Although this is an exercise, the `encrypt` and `decrypt` functions should
provide reasonable security to encrypted messages.
"""


s_box = bytes([ 0x1C, 0x2F, 0x03, 0x53, 0xA3, 0x01, 0x49, 0xDA, 0xA6, 0xCD, 0xE0, 0x8A, 0x19, 0xA7, 0x04, 0xD4,
							0x06, 0x1A, 0xDA, 0x49, 0x08, 0xE2, 0xF6, 0xB2, 0x9E, 0xE1, 0x22, 0x49, 0xCE, 0x7B, 0x7E, 0x5E,
							0xA0, 0x09, 0x2A, 0x63, 0xAF, 0x49, 0xCE, 0x70, 0x7B, 0x3C, 0x23, 0x80, 0xFA, 0x17, 0x47, 0xF2,
							0x62, 0x62, 0x6C, 0x59, 0x10, 0xCC, 0x29, 0x9C, 0xB5, 0x46, 0x58, 0xC7, 0x44, 0x13, 0xE7, 0x38,
							0xD5, 0xAF, 0x27, 0x83, 0xD4, 0xD5, 0xA0, 0x9E, 0xE3, 0x76, 0x3B, 0x85, 0x04, 0xD9, 0xD6, 0x98,
							0x60, 0x66, 0xD4, 0x78, 0x53, 0xEA, 0xCA, 0x0E, 0x8D, 0x56, 0x53, 0x44, 0xE2, 0xEF, 0xBD, 0xA9,
							0x9B, 0x10, 0x0A, 0xA1, 0x13, 0x93, 0xF0, 0x43, 0x0B, 0x7C, 0x39, 0x8A, 0x47, 0xDF, 0xD3, 0xC5,
							0x0E, 0x34, 0x31, 0xA6, 0xAE, 0x5A, 0xB8, 0xE7, 0xE6, 0x31, 0x43, 0xC0, 0xAA, 0x0F, 0xE0, 0x82,
							0x12, 0x4C, 0xD1, 0xDF, 0x8B, 0xA5, 0xAC, 0x70, 0xC5, 0x3D, 0x1B, 0x8E, 0x93, 0x17, 0x4D, 0x79,
							0x4E, 0xCE, 0x63, 0xC4, 0x33, 0x0E, 0x14, 0x57, 0xF0, 0xD8, 0x19, 0x5B, 0x9B, 0x61, 0x71, 0xF2,
							0x2B, 0x33, 0x7E, 0xFD, 0x2C, 0x0B, 0xB6, 0x23, 0x20, 0xB9, 0xD4, 0x91, 0x19, 0x94, 0x04, 0xA4,
							0x30, 0x13, 0x8A, 0xF1, 0xD0, 0x05, 0xEC, 0x5E, 0xAC, 0x4A, 0xD4, 0xD6, 0xA5, 0x17, 0x7F, 0xF9,
							0xE5, 0xF6, 0x00, 0x29, 0xD7, 0x93, 0x2D, 0x5E, 0x2C, 0xF1, 0x81, 0xA3, 0xB7, 0x63, 0x39, 0x57,
							0xC2, 0x33, 0x87, 0x2D, 0xA8, 0x3F, 0x02, 0xCC, 0x08, 0x67, 0x74, 0x60, 0xD8, 0xF0, 0xDA, 0x67,
							0x40, 0x64, 0x87, 0x55, 0xBB, 0x7F, 0xF2, 0x10, 0xC9, 0x03, 0x14, 0xB5, 0x80, 0x66, 0xCB, 0x91,
							0xF6, 0x1F, 0x79, 0x58, 0x88, 0xBC, 0x95, 0xC2, 0x06, 0x5F, 0xE9, 0x09, 0x32, 0xED, 0x9B, 0x85 
])

inv_s_box = s_box


def sub_bytes(s):
    for i in range(4):
        for j in range(4):
            s[i][j] = s_box[s[i][j]]


def inv_sub_bytes(s):
    for i in range(4):
        for j in range(4):
            s[i][j] = inv_s_box[s[i][j]]


def shift_rows(s):
    s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3]


def inv_shift_rows(s):
    s[0][1], s[1][1], s[2][1], s[3][1] = s[3][1], s[0][1], s[1][1], s[2][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[1][3], s[2][3], s[3][3], s[0][3]

def add_round_key(s, k):
    for i in range(4):
        for j in range(4):
            s[i][j] ^= k[i][j]


# learned from https://web.archive.org/web/20100626212235/http://cs.ucsb.edu/~koc/cs178/projects/JT/aes.c
xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)


def mix_single_column(a):
    # see Sec 4.1.2 in The Design of Rijndael
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    u = a[0]
    a[0] ^= t ^ xtime(a[0] ^ a[1])
    a[1] ^= t ^ xtime(a[1] ^ a[2])
    a[2] ^= t ^ xtime(a[2] ^ a[3])
    a[3] ^= t ^ xtime(a[3] ^ u)


def mix_columns(s):
    for i in range(4):
        mix_single_column(s[i])


def inv_mix_columns(s):
    # see Sec 4.1.3 in The Design of Rijndael
    for i in range(4):
        u = xtime(xtime(s[i][0] ^ s[i][2]))
        v = xtime(xtime(s[i][1] ^ s[i][3]))
        s[i][0] ^= u
        s[i][1] ^= v
        s[i][2] ^= u
        s[i][3] ^= v

    mix_columns(s)


r_con = (
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
    0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
    0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
)


def bytes2matrix(text):
    """ Converts a 16-byte array into a 4x4 matrix.  """
    return [list(text[i:i+4]) for i in range(0, len(text), 4)]

def matrix2bytes(matrix):
    """ Converts a 4x4 matrix into a 16-byte array.  """
    return bytes(sum(matrix, []))

def xor_bytes(a, b):
    """ Returns a new byte array with the elements xor'ed. """
    return bytes(i^j for i, j in zip(a, b))

def inc_bytes(a):
    """ Returns a new byte array with the value increment by 1 """
    out = list(a)
    for i in reversed(range(len(out))):
        if out[i] == 0xFF:
            out[i] = 0
        else:
            out[i] += 1
            break
    return bytes(out)

def pad(plaintext):
    """
    Pads the given plaintext with PKCS#7 padding to a multiple of 16 bytes.
    Note that if the plaintext size is a multiple of 16,
    a whole block will be added.
    """
    padding_len = 16 - (len(plaintext) % 16)
    padding = bytes([padding_len] * padding_len)
    return plaintext + padding

def unpad(plaintext):
    """
    Removes a PKCS#7 padding, returning the unpadded text and ensuring the
    padding was correct.
    """
    padding_len = plaintext[-1]
    assert padding_len > 0
    message, padding = plaintext[:-padding_len], plaintext[-padding_len:]
    assert all(p == padding_len for p in padding)
    return message

def split_blocks(message, block_size=16, require_padding=True):
        assert len(message) % block_size == 0 or not require_padding
        return [message[i:i+16] for i in range(0, len(message), block_size)]


class AES:
    """
    Class for AES-128 encryption with CBC mode and PKCS#7.

    This is a raw implementation of AES, without key stretching or IV
    management. Unless you need that, please use `encrypt` and `decrypt`.
    """
    rounds_by_key_size = {16: 10, 24: 12, 32: 14}
    def __init__(self, master_key):
        """
        Initializes the object with a given key.
        """
        assert len(master_key) in AES.rounds_by_key_size
        self.n_rounds = AES.rounds_by_key_size[len(master_key)]
        self._key_matrices = self._expand_key(master_key)

    def _expand_key(self, master_key):
        """
        Expands and returns a list of key matrices for the given master_key.
        """
        # CUSTOM MODIFICATION: Reverse each 4-byte word to match C++ implementation
        key_bytes = bytearray(master_key)
        for i in range(0, len(key_bytes), 4):
            # Reverse each 4-byte word: [0,1,2,3] becomes [3,2,1,0]
            key_bytes[i:i+4] = key_bytes[i:i+4][::-1]
        
        # Initialize round keys with raw key material.
        key_columns = bytes2matrix(bytes(key_bytes))
        iteration_size = len(master_key) // 4

        i = 1
        while len(key_columns) < (self.n_rounds + 1) * 4:
            # Copy previous word.
            word = list(key_columns[-1])

            # Perform schedule_core once every "row".
            if len(key_columns) % iteration_size == 0:
                # Circular shift.
                word.append(word.pop(0))
                # Map to S-BOX.
                word = [s_box[b] for b in word]
                # XOR with first byte of R-CON, since the others bytes of R-CON are 0.
                word[0] ^= r_con[i]
                i += 1
            elif len(master_key) == 32 and len(key_columns) % iteration_size == 4:
                # Run word through S-box in the fourth iteration when using a
                # 256-bit key.
                word = [s_box[b] for b in word]

            # XOR with equivalent word from previous iteration.
            word = xor_bytes(word, key_columns[-iteration_size])
            key_columns.append(word)

        # Group key words in 4x4 byte matrices.
        return [key_columns[4*i : 4*(i+1)] for i in range(len(key_columns) // 4)]

    def encrypt_block(self, plaintext):
        """
        Encrypts a single block of 16 byte long plaintext.
        """
        assert len(plaintext) == 16

        plain_state = bytes2matrix(plaintext)

        add_round_key(plain_state, self._key_matrices[0])

        for i in range(1, self.n_rounds):
            sub_bytes(plain_state)
            shift_rows(plain_state)
            mix_columns(plain_state)
            add_round_key(plain_state, self._key_matrices[i])

        sub_bytes(plain_state)
        shift_rows(plain_state)
        add_round_key(plain_state, self._key_matrices[-1])

        return matrix2bytes(plain_state)

    def decrypt_block(self, ciphertext):
        """
        Decrypts a single block of 16 byte long ciphertext.
        """
        assert len(ciphertext) == 16

        cipher_state = bytes2matrix(ciphertext)

        add_round_key(cipher_state, self._key_matrices[-1])
        inv_shift_rows(cipher_state)
        inv_sub_bytes(cipher_state)

        for i in range(self.n_rounds - 1, 0, -1):
            add_round_key(cipher_state, self._key_matrices[i])
            inv_mix_columns(cipher_state)
            inv_shift_rows(cipher_state)
            inv_sub_bytes(cipher_state)

        add_round_key(cipher_state, self._key_matrices[0])

        return matrix2bytes(cipher_state)

    def encrypt_cbc(self, plaintext, iv):
        """
        Encrypts `plaintext` using CBC mode and PKCS#7 padding, with the given
        initialization vector (iv).
        """
        assert len(iv) == 16

        plaintext = pad(plaintext)

        blocks = []
        previous = iv
        for plaintext_block in split_blocks(plaintext):
            # CBC mode encrypt: encrypt(plaintext_block XOR previous)
            block = self.encrypt_block(xor_bytes(plaintext_block, previous))
            blocks.append(block)
            previous = block

        return b''.join(blocks)

    def decrypt_cbc(self, ciphertext, iv):
        """
        Decrypts `ciphertext` using CBC mode and PKCS#7 padding, with the given
        initialization vector (iv).
        """
        assert len(iv) == 16

        blocks = []
        previous = iv
        for ciphertext_block in split_blocks(ciphertext):
            # CBC mode decrypt: previous XOR decrypt(ciphertext)
            blocks.append(xor_bytes(previous, self.decrypt_block(ciphertext_block)))
            previous = ciphertext_block

        return unpad(b''.join(blocks))

    def encrypt_pcbc(self, plaintext, iv):
        """
        Encrypts `plaintext` using PCBC mode and PKCS#7 padding, with the given
        initialization vector (iv).
        """
        assert len(iv) == 16

        plaintext = pad(plaintext)

        blocks = []
        prev_ciphertext = iv
        prev_plaintext = bytes(16)
        for plaintext_block in split_blocks(plaintext):
            # PCBC mode encrypt: encrypt(plaintext_block XOR (prev_ciphertext XOR prev_plaintext))
            ciphertext_block = self.encrypt_block(xor_bytes(plaintext_block, xor_bytes(prev_ciphertext, prev_plaintext)))
            blocks.append(ciphertext_block)
            prev_ciphertext = ciphertext_block
            prev_plaintext = plaintext_block

        return b''.join(blocks)

    def decrypt_pcbc(self, ciphertext, iv):
        """
        Decrypts `ciphertext` using PCBC mode and PKCS#7 padding, with the given
        initialization vector (iv).
        """
        assert len(iv) == 16

        blocks = []
        prev_ciphertext = iv
        prev_plaintext = bytes(16)
        for ciphertext_block in split_blocks(ciphertext):
            # PCBC mode decrypt: (prev_plaintext XOR prev_ciphertext) XOR decrypt(ciphertext_block)
            plaintext_block = xor_bytes(xor_bytes(prev_ciphertext, prev_plaintext), self.decrypt_block(ciphertext_block))
            blocks.append(plaintext_block)
            prev_ciphertext = ciphertext_block
            prev_plaintext = plaintext_block

        return unpad(b''.join(blocks))

    def encrypt_cfb(self, plaintext, iv):
        """
        Encrypts `plaintext` with the given initialization vector (iv).
        """
        assert len(iv) == 16

        blocks = []
        prev_ciphertext = iv
        for plaintext_block in split_blocks(plaintext, require_padding=False):
            # CFB mode encrypt: plaintext_block XOR encrypt(prev_ciphertext)
            ciphertext_block = xor_bytes(plaintext_block, self.encrypt_block(prev_ciphertext))
            blocks.append(ciphertext_block)
            prev_ciphertext = ciphertext_block

        return b''.join(blocks)

    def decrypt_cfb(self, ciphertext, iv):
        """
        Decrypts `ciphertext` with the given initialization vector (iv).
        """
        assert len(iv) == 16

        blocks = []
        prev_ciphertext = iv
        for ciphertext_block in split_blocks(ciphertext, require_padding=False):
            # CFB mode decrypt: ciphertext XOR decrypt(prev_ciphertext)
            plaintext_block = xor_bytes(ciphertext_block, self.encrypt_block(prev_ciphertext))
            blocks.append(plaintext_block)
            prev_ciphertext = ciphertext_block

        return b''.join(blocks)

    def encrypt_ofb(self, plaintext, iv):
        """
        Encrypts `plaintext` using OFB mode initialization vector (iv).
        """
        assert len(iv) == 16

        blocks = []
        previous = iv
        for plaintext_block in split_blocks(plaintext, require_padding=False):
            # OFB mode encrypt: plaintext_block XOR encrypt(previous)
            block = self.encrypt_block(previous)
            ciphertext_block = xor_bytes(plaintext_block, block)
            blocks.append(ciphertext_block)
            previous = block

        return b''.join(blocks)

    def decrypt_ofb(self, ciphertext, iv):
        """
        Decrypts `ciphertext` using OFB mode initialization vector (iv).
        """
        assert len(iv) == 16

        blocks = []
        previous = iv
        for ciphertext_block in split_blocks(ciphertext, require_padding=False):
            # OFB mode decrypt: ciphertext XOR encrypt(previous)
            block = self.encrypt_block(previous)
            plaintext_block = xor_bytes(ciphertext_block, block)
            blocks.append(plaintext_block)
            previous = block

        return b''.join(blocks)

    def encrypt_ctr(self, plaintext, iv):
        """
        Encrypts `plaintext` using CTR mode with the given nounce/IV.
        """
        assert len(iv) == 16

        blocks = []
        nonce = iv
        for plaintext_block in split_blocks(plaintext, require_padding=False):
            # CTR mode encrypt: plaintext_block XOR encrypt(nonce)
            block = xor_bytes(plaintext_block, self.encrypt_block(nonce))
            blocks.append(block)
            nonce = inc_bytes(nonce)

        return b''.join(blocks)

    def decrypt_ctr(self, ciphertext, iv):
        """
        Decrypts `ciphertext` using CTR mode with the given nounce/IV.
        """
        assert len(iv) == 16

        blocks = []
        nonce = iv
        for ciphertext_block in split_blocks(ciphertext, require_padding=False):
            # CTR mode decrypt: ciphertext XOR encrypt(nonce)
            block = xor_bytes(ciphertext_block, self.encrypt_block(nonce))
            blocks.append(block)
            nonce = inc_bytes(nonce)

        return b''.join(blocks)


import os
from hashlib import pbkdf2_hmac
from hmac import new as new_hmac, compare_digest

AES_KEY_SIZE = 16
HMAC_KEY_SIZE = 16
IV_SIZE = 16

SALT_SIZE = 16
HMAC_SIZE = 32

def get_key_iv(password, salt, workload=100000):
    """
    Stretches the password and extracts an AES key, an HMAC key and an AES
    initialization vector.
    """
    stretched = pbkdf2_hmac('sha256', password, salt, workload, AES_KEY_SIZE + IV_SIZE + HMAC_KEY_SIZE)
    aes_key, stretched = stretched[:AES_KEY_SIZE], stretched[AES_KEY_SIZE:]
    hmac_key, stretched = stretched[:HMAC_KEY_SIZE], stretched[HMAC_KEY_SIZE:]
    iv = stretched[:IV_SIZE]
    return aes_key, hmac_key, iv


def encrypt(key, plaintext, workload=100000):
    """
    Encrypts `plaintext` with `key` using AES-128, an HMAC to verify integrity,
    and PBKDF2 to stretch the given key.

    The exact algorithm is specified in the module docstring.
    """
    if isinstance(key, str):
        key = key.encode('utf-8')
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')

    salt = os.urandom(SALT_SIZE)
    key, hmac_key, iv = get_key_iv(key, salt, workload)
    ciphertext = AES(key).encrypt_cbc(plaintext, iv)
    hmac = new_hmac(hmac_key, salt + ciphertext, 'sha256').digest()
    assert len(hmac) == HMAC_SIZE

    return hmac + salt + ciphertext


def decrypt(key, ciphertext, workload=100000):
    """
    Decrypts `ciphertext` with `key` using AES-128, an HMAC to verify integrity,
    and PBKDF2 to stretch the given key.

    The exact algorithm is specified in the module docstring.
    """

    assert len(ciphertext) % 16 == 0, "Ciphertext must be made of full 16-byte blocks."

    assert len(ciphertext) >= 32, """
    Ciphertext must be at least 32 bytes long (16 byte salt + 16 byte block). To
    encrypt or decrypt single blocks use `AES(key).decrypt_block(ciphertext)`.
    """

    if isinstance(key, str):
        key = key.encode('utf-8')

    hmac, ciphertext = ciphertext[:HMAC_SIZE], ciphertext[HMAC_SIZE:]
    salt, ciphertext = ciphertext[:SALT_SIZE], ciphertext[SALT_SIZE:]
    key, hmac_key, iv = get_key_iv(key, salt, workload)

    expected_hmac = new_hmac(hmac_key, salt + ciphertext, 'sha256').digest()
    assert compare_digest(hmac, expected_hmac), 'Ciphertext corrupted or tampered.'

    return AES(key).decrypt_cbc(ciphertext, iv)


def benchmark():
    key = b'P' * 16
    message = b'M' * 16
    aes = AES(key)
    for i in range(30000):
        aes.encrypt_block(message)

__all__ = ["encrypt", "decrypt", "AES"]

if __name__ == '__main__':
    import sys
    write = lambda b: sys.stdout.buffer.write(b)
    read = lambda: sys.stdin.buffer.read()

    if len(sys.argv) < 2:
        print('Usage: ./aes.py encrypt "key" "message"')
        print('Running tests...')
        from tests import *
        run()
    elif len(sys.argv) == 2 and sys.argv[1] == 'benchmark':
        benchmark()
        exit()
    elif len(sys.argv) == 3:
        text = read()
    elif len(sys.argv) > 3:
        text = ' '.join(sys.argv[2:])

    if 'encrypt'.startswith(sys.argv[1]):
        write(encrypt(sys.argv[2], text))
    elif 'decrypt'.startswith(sys.argv[1]):
        write(decrypt(sys.argv[2], text))
    else:
        print('Expected command "encrypt" or "decrypt" in first argument.')

    # encrypt('my secret key', b'0' * 1000000) # 1 MB encrypted in 20 seconds.
