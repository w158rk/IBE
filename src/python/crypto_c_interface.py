#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

'''
@File    :   crypto_c_interface.py
@Time    :   2020/05/16 21:03:05
@Author  :   Ruikai Wang
@Version :   1.0
@Contact :   wrk15835@gmail.com
@License :   Copyright (c) 2020 Ruikai Wang
@Desc    :   interface between the python code and C library for cryptographic algorithms
'''

from ctypes import c_char, c_char_p,  c_int, c_ulong, c_long, create_string_buffer, POINTER, CDLL, pointer, cast
import os
import time
import argparse
from constant import *
from utils import str2bytes

"""
global variables
"""


_encrypt_only = False

PCHAR = POINTER(c_char)
PPCHAR = POINTER(c_char_p)


def ibe_setup(mpk_file, msk_file, mpk_len_file, msk_len_file):
    """Setup a subsystem

    Setup a subsystem, output the related public master key
    and master key to the file system

    Args:
        mpk_file: filename of the file to put public master key
        msk_file: filename of the file to put master key
        mpk_len_file: filename of the file to put the length of the public master key
        msk_len_file: filename of the file to put the length of the master key

        ATTENTION: all the filenames should be in bytes type rather than string

    Returns:
        1 if all works well
        0 else

    Raises:
        TypeError if the filenames are not in the proper type
        TODO(wrk): unclear
    """

    try:
        c_mpk_file = create_string_buffer(mpk_file)
        c_msk_file = create_string_buffer(msk_file)
        c_mpk_len_file = create_string_buffer(mpk_len_file)
        c_msk_len_file = create_string_buffer(msk_len_file)
    except TypeError:
        raise TypeError("the filenames should be in bytes type, "
                        "try add b in front of the \"")
    lib_ibe = CDLL(LIBIBE_PATH)
    res = lib_ibe.ibe_setup(c_mpk_file, c_msk_file, c_mpk_len_file, c_msk_len_file)
    return res


def ibe_read_from_file(filename):
    """read the files with (public) master keys"""
    with open(filename, "rb") as f:
        res = f.read()
        return res
    return None


def ibe_write_to_file(content, filename):
    """write to the file"""
    with open(filename, "wb") as f:
        f.write(content)


def ibe_extract_file(msk, user_id, sk_file):
    """extract the private key for given ID

    given the master key and the id, return the corresponding private key

    Args:
        msk: the bytes read representing for master key, often read from msk_file
        user_id: the user ID, in bytes type

    Returns:
        the bytes object for the private key if success, None else
    """

    sk = c_char_p(None)
    p_sk = PPCHAR(sk)       # TODO(wrk): still not figure out how to create a NULL pointer

    sk_len = c_int(0)
    p_sk_len = pointer(sk_len)

    # use the following code to generate a char ** pointer
    # using create_string_buffer would create a char[]
    # it will trigger the bus error if using inappropriately

    c_msk = c_char_p()
    c_msk.value = msk
    p_msk = pointer(c_msk)
    c_msk_len = len(msk)

    c_id = c_char_p()
    c_id.value = user_id
    c_id_len = len(user_id)

    lib_ibe = CDLL(LIBIBE_PATH)
    res = lib_ibe.ibe_extract(p_sk, p_sk_len, p_msk, c_msk_len, c_id, c_id_len)
    if res:
        sk_len = p_sk_len.contents
        sk_len = sk_len.value

        # As the attribute `value` of a c_char_p object is a string that ends with
        # '\0', so usually the length of the `value` is shorter than the actual length
        # of private keys. So we have to read the private key byte by byte.
        # By the way, as the c_char_p object does not support the index [],
        # so use the `cast` function to cast it to POINTER(c_char) is the
        # appropriate method

        sk = p_sk.contents
        sk = cast(sk, PCHAR)

        res = []
        for i in range(sk_len):
            res.append(sk[i])

        re = b''.join(res)

        ibe_write_to_file(re, sk_file)

def ibe_extract(msk, user_id):
    """extract the private key for given ID

    given the master key and the id, return the corresponding private key

    Args:
        msk: the bytes read representing for master key, often read from msk_file
        user_id: the user ID, in bytes type

    Returns:
        the bytes object for the private key if success, None else
    """

    sk = c_char_p(None)
    p_sk = PPCHAR(sk)       # TODO(wrk): still not figure out how to create a NULL pointer

    sk_len = c_int(0)
    p_sk_len = pointer(sk_len)

    # use the following code to generate a char ** pointer
    # using create_string_buffer would create a char[]
    # it will trigger the bus error if using inappropriately

    c_msk = c_char_p()
    c_msk.value = msk
    p_msk = pointer(c_msk)
    c_msk_len = len(msk)

    c_id = c_char_p()
    c_id.value = user_id
    c_id_len = len(user_id)

    lib_ibe = CDLL(LIBIBE_PATH)
    res = lib_ibe.ibe_extract(p_sk, p_sk_len, p_msk, c_msk_len, c_id, c_id_len)
    if res:
        sk_len = p_sk_len.contents
        sk_len = sk_len.value

        # As the attribute `value` of a c_char_p object is a string that ends with
        # '\0', so usually the length of the `value` is shorter than the actual length
        # of private keys. So we have to read the private key byte by byte.
        # By the way, as the c_char_p object does not support the index [],
        # so use the `cast` function to cast it to POINTER(c_char) is the
        # appropriate method

        sk = p_sk.contents
        sk = cast(sk, PCHAR)

        res = []
        for i in range(sk_len):
            res.append(sk[i])

        return b''.join(res)
    else:
        return None


def ibe_encrypt(m, mpk, user_id):
    """encrypt the message with public master key and id

    Args:
        m: message to be encrypted
        mpk: public master key
        user_id

        ATTENTION: all arguments should be in bytes type

    Return:
        cipher, in bytes type
    """

    c_m = c_char_p()
    c_m.value = m
    m_len = len(m)
    c_m_len = c_ulong(m_len)

    c_c = c_char_p()
    c_c.value = b"\x00" * BUFFER_SIZE
    c_c_len = c_ulong(BUFFER_SIZE)
    p_c_len = pointer(c_c_len)

    c_mpk = c_char_p()
    c_mpk.value = mpk
    p_mpk = pointer(c_mpk)
    c_mpk_len = len(mpk)

    c_id = c_char_p()
    c_id.value = user_id
    c_id_len = len(user_id)

    # ATTENTION: Never pass a python int object to a size_t type variable in C!
    c_id_len = c_ulong(c_id_len)

    lib_ibe = CDLL(LIBIBE_PATH)
    res = lib_ibe.ibe_encrypt(c_m, c_m_len, c_c, p_c_len, p_mpk, c_mpk_len, c_id, c_id_len)

    if res:

        c_len = p_c_len.contents.value

        # even with pre-defined buffer, the value attribute is a string ended with '\0',
        # which means if there is any '\0' in the byte string, the value be the
        # longest prefix without '\0'. So still, we have to do a cast and collect
        # the string manually

        c_c = cast(c_c, PCHAR)

        res = []
        for i in range(c_len):
            res.append(c_c[i])

        return b''.join(res)

    return None


def ibe_decrypt(c, sk):
    """decrypt the cipher with private key

    Args:
        c: the cipher
        sk: the private key

        ATTENTION: all in bytes type

    Returns:
        the decrypted message, in bytes type
    """

    c_c = c_char_p()
    c_c.value = c
    c_len = len(c)
    c_c_len = c_ulong(c_len)

    c_m = c_char_p()
    c_m.value = b"\x00" * BUFFER_SIZE
    c_m_len = c_ulong(BUFFER_SIZE)
    p_m_len = pointer(c_m_len)

    c_sk = c_char_p()
    c_sk.value = sk
    p_sk = pointer(c_sk)
    sk_len = len(sk)
    c_sk_len = c_long(sk_len)

    lib_ibe = CDLL(LIBIBE_PATH)
    res = lib_ibe.ibe_decrypt(c_c, c_c_len, c_m, p_m_len, p_sk, c_sk_len)

    assert res

    m_len = p_m_len.contents.value
    m = cast(c_m, PCHAR)
    res = []
    for i in range(m_len):
        res.append(m[i])

    return b"".join(res)


def ibe_sign(m, sk):
    """sign the message with private key

    Args:
        m: the message
        sk: the private key

        ATTENTION: all in bytes type

    Returns:
        the sign message, in bytes type
    """

    c_m = c_char_p()
    c_m.value = m
    m_len = len(m)
    c_m_len = c_ulong(m_len)

    c_s = c_char_p()
    c_s.value = b"\x00" * BUFFER_SIZE
    c_s_len = c_ulong(BUFFER_SIZE)
    p_s_len = pointer(c_s_len)

    c_sk = c_char_p()
    c_sk.value = sk
    p_sk = pointer(c_sk)
    sk_len = len(sk)
    c_sk_len = c_long(sk_len)

    lib_ibe = CDLL(LIBIBE_PATH)
    res = lib_ibe.ibe_sign(c_m, c_m_len, c_s, p_s_len, p_sk, c_sk_len)

    if res:
        s_len = p_s_len.contents.value
        c_s = cast(c_s, PCHAR)

        res = []
        for i in range(s_len):
            res.append(c_s[i])

        return b''.join(res)

    return None


def ibe_verify(m, sm, mpk, user_id):
    """verify the signed-message with public master key and id

    Args:
        m: message
        sm: signed-message
        mpk: public master key
        user_id

        ATTENTION: all arguments should be in bytes type

    Return:
        1 for pass, -1 for fail
    """

    time_start = time.time()

    c_m = c_char_p()
    c_m.value = m
    m_len = len(m)
    c_m_len = c_ulong(m_len)

    c_sm = c_char_p()
    c_sm.value = sm
    sm_len = len(sm)
    c_sm_len = c_ulong(sm_len)

    c_mpk = c_char_p()
    c_mpk.value = mpk
    p_mpk = pointer(c_mpk)
    c_mpk_len = len(mpk)

    c_id = c_char_p()
    c_id.value = user_id
    c_id_len = len(user_id)
    c_id_len = c_ulong(c_id_len)

    lib_ibe = CDLL(LIBIBE_PATH)
    res = lib_ibe.ibe_verify(c_m, c_m_len, c_sm, c_sm_len, p_mpk, c_mpk_len, c_id, c_id_len)
    print(res)
    time_end = time.time()
    print('verify totally cost', time_end-time_start)

    return res


def sm4_enc(key, m):
    """encrypt the message with sm4 key

    Args:
        key: sm4 key
        m: message to be encrypted

    Return:
        cipher
    """

    c_key = c_char_p()
    c_key.value = key

    c_m = c_char_p()
    c_m.value = m
    m_len = len(m)
    c_m_len = c_ulong(m_len)

    c_c = c_char_p()
    c_len = m_len + 32 # for ensurance
    c_c.value = b"\x00" * c_len
    c_c_len = c_ulong(c_len)
    p_c_len = pointer(c_c_len)

    lib_ibe = CDLL(LIBIBE_PATH)
    res = lib_ibe.sym_crypt_ecb(c_key, 1, c_m_len, c_m, c_c, p_c_len)

    if res:
        c_len = p_c_len.contents.value

        c_c = cast(c_c, PCHAR)

        res = []
        for i in range(c_len):
            res.append(c_c[i])

        return b''.join(res)

    return None


def sm4_dec(key, c):
    """decrypt the cipher with sm4 key

    Args:
        key: sm4 key
        c: the cipher

    Return:
        the decrypted message
    """

    c_key = c_char_p()
    c_key.value = key

    c_c = c_char_p()
    c_c.value = c
    c_len = len(c)
    c_c_len = c_ulong(c_len)

    c_m = c_char_p()
    m_len = c_len + 32
    c_m.value = b"\x00" * m_len
    c_m_len = c_ulong(m_len)
    p_m_len = pointer(c_m_len)

    lib_ibe = CDLL(LIBIBE_PATH)
    res = lib_ibe.sym_crypt_ecb(c_key, 0, c_c_len, c_c, c_m, p_m_len)

    if res:
        m_len = p_m_len.contents.value

        c_m = cast(c_m, PCHAR)

        res = []

        # TODO(wxy): this is very inappropriate to handle the decrypted text this way
        # it should be replaced soon
        for i in range(m_len):
            if(c_m[i]==b'\x00'):
                break
            res.append(c_m[i])

        return b''.join(res)

    return None


class CryptoTest(object):
    """class for testing the cryptographic algorithms

    Attributes:
        mpk_file: filename of the file to put public master key
        msk_file: filename of the file to put master key
        mpk_file: filename of the file to put the length of the public master key
        mpk_file: filename of the file to put the length of the master key
        user_id: user_id for test
        mpk: public master key
        msk: master key
        sk: private key
        m: message
        c: cipher
        dm: decrypted message
        sm4_key: key for sm4
    """

    def __init__(self, mpk_file=b"mpk", msk_file=b"msk",
                 mpk_len_file=b"mpk_len", msk_len_file=b"msk_len",
                 sk_file=b"sk",
                 user_id=b"Server1", m=b"This is a test text",
                 sm4_key=b"1234567812345678"):

        self.mpk_file = mpk_file
        self.msk_file = msk_file
        self.mpk_len_file = mpk_len_file
        self.msk_len_file = msk_len_file
        self.sk_file = sk_file
        self.user_id = user_id
        self.m = m
        self.sm4_key = sm4_key

        self.mpk = None
        self.msk = None
        self.sk = None
        self.c = None
        self.dm = None
        self.sm = None

        if _encrypt_only:
            self.mpk = ibe_read_from_file(mpk_file)
            self.sk = ibe_read_from_file(sk_file)

    def test_ibe_setup(self):
        res = ibe_setup(self.mpk_file, self.msk_file,
                        self.mpk_len_file, self.msk_len_file)
        if res:
            print("test ibe_setup passed!")
            self.mpk = ibe_read_from_file(self.mpk_file)
            self.msk = ibe_read_from_file(self.msk_file)
            return True
        else:
            print("test ibe_setup failed!")
            return False

    def test_ibe_extract(self):
        if not self.msk:
            print("read msk failed!")
            return False
        sk = ibe_extract(self.msk, self.user_id)
        if not sk:
            print("extract private key failed!")
            return False
        print("extract private key passed!")
        self.sk = sk
        return True

    def test_ibe_encrypt(self):
        if not self.mpk:
            print("read mpk failed!")
            return False
        c = ibe_encrypt(self.m, self.mpk, self.user_id)
        if c:
            print("encrypt test passed!")
            self.c = c
            return True
        else:
            print("encrypt test failed")
            return False

    def test_ibe_decrypt(self):
        if not self.sk:
            print("read sk failed!")
            return False

        dm = ibe_decrypt(self.c, self.sk)
        if dm and dm == self.m:
            print("decrypt test passed!")
            self.dm = dm
            return True
        else:
            print("decrypt test failed!")
            print(list(self.m))
            print(list(dm))
            return False

    def test_ibe_sign(self):
        if not self.sk:
            print("read sk failed!")
            return False
        sm = ibe_sign(self.m, self.sk)
        if sm:
            print("sign test passed!")
            self.sm = sm
            return True
        else:
            print("sign test failed!")
            return False

    def test_ibe_verify(self):
        if not self.mpk:
            print("read mpk failed!")
            return False
        res = ibe_verify(self.m, self.sm, self.mpk, self.user_id)

        if res == 1:
            print("verify test passed!")
            return True
        else:
            print("verify test failed!")
            return False

    def test_sm4_enc(self):
        if not self.sm4_key:
            print("read sm4_key failed!")
            return False
        c = sm4_enc(self.sm4_key, self.m)
        if c:
            print("encrypt test passed!")
            self.c = c
            return True
        else:
            print("encrypt test failed")
            return False

    def test_sm4_dec(self):
        if not self.sm4_key:
            print("read sm4_key failed!")
            return False
        dm = sm4_dec(self.sm4_key, self.c)

        if dm and dm == self.m:
            print("decrypt test passed!")
            self.dm = dm
            return True
        else:
            print("decrypt test failed!")
            print(list(self.m))
            print(list(dm))
            return False

    def remove_auxiliary_files(self):
        for filename in [self.mpk_file, self.mpk_len_file,
                         self.msk_file, self.msk_len_file]:
            if os.path.exists(filename):
                os.remove(filename)

    def test_all(self, clean_after_test=True):
        res = True
        res = res and self.test_ibe_setup()
        res = res and self.test_ibe_extract()
        res = res and self.test_ibe_encrypt()
        res = res and self.test_ibe_decrypt()
        res = res and self.test_ibe_sign()
        res = res and self.test_ibe_verify()
        res = res and self.test_sm4_enc()
        res = res and self.test_sm4_dec()

        if res:
            print("test all passed!")

        if clean_after_test:
            self.remove_auxiliary_files()

    def test_encrypt(self):
        """
        This is for testing if an sk file is correctly generated
        the following files are required:
            self.mpk_file
            self.sk_file
        """
        if not os.path.exists(self.mpk_file):
            raise Exception("%s does not exist" % self.mpk_file)

        if not os.path.exists(self.sk_file):
            raise Exception("%s does not exist" % self.sk_file)

        res = True
        res = res and self.test_ibe_encrypt()
        res = res and self.test_ibe_decrypt()

        if res:
            print("test all passed!")


def main():
    """main function
    """

    parser = argparse.ArgumentParser(description='test crypto function')
    parser.add_argument('-e',  dest="encrypt_only", action="store_true",
                        help='test the functionality of encrypt and decrypt only')
    parser.add_argument('-id', type=str,  dest="user_id", help='the user id')
    parser.add_argument('-sk', type=str,  dest="sk_file", help='the sk file')
    parser.add_argument('-mpk', type=str,  dest="mpk_file", help='the mpk file')
    parser.add_argument('-msk', type=str,  dest="msk_file", help='the msk file')
    args = parser.parse_args()
    global _encrypt_only
    _encrypt_only = args.encrypt_only

    if _encrypt_only:
        "the following three args must be in place"
        mpk_file = str2bytes(args.mpk_file)
        user_id = str2bytes(args.user_id)
        sk_file = str2bytes(args.sk_file)
        cryptoTest = CryptoTest(mpk_file=mpk_file, sk_file=sk_file, user_id=user_id)
        cryptoTest.test_encrypt()
    else:
        cryptoTest = CryptoTest()
        cryptoTest.test_all(False)


if __name__ == "__main__":
    main()
