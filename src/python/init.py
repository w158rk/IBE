#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

'''
@File    :   init.py
@Time    :   2020/06/02 09:43:24
@Author  :   Ruikai Wang 
@Version :   1.0
@Contact :   wrk15835@gmail.com
@License :   Copyright (c) 2020 Ruikai Wang
@Desc    :   The util functions for initialization phase
'''

from ctypes import c_char, c_char_p,  c_int, c_ulong, c_long, create_string_buffer, POINTER, CDLL, pointer, cast
from constant import *
import os


PCHAR = POINTER(c_char)
PPCHAR = POINTER(c_char_p)

def SS_cal_share(val_list, id_list, mpk_file=b"./mpk"):
    assert(len(val_list) == len(id_list))

    length = len(val_list)
    c_len = c_int(length)

    str_val_list = b''.join(val_list)
    c_val_list = c_char_p()
    c_val_list.value = str_val_list
    c_val_list = cast(c_val_list, PCHAR)

    str_id_list = b'\0'.join(id_list)
    c_id_list = c_char_p()
    c_id_list.value = str_id_list
    c_id_list = cast(c_id_list, PCHAR)

    c_id_len_list = (c_int * length)()
    for i in range(length):
        c_id_len_list[i] = c_int(len(id_list[i]))

    c_mpk_file = c_char_p()
    c_mpk_file.value = mpk_file

    lib_ibe = CDLL(LIBIBE_PATH)
    cal = lib_ibe.SS_cal_share_py
    cal.argtypes = ([c_int, PCHAR, PCHAR, c_int * length, c_char_p])
    cal.restype = (c_char_p)    

    res = cal(c_len, c_val_list, c_id_list, c_id_len_list, c_mpk_file)
    return res

def SS_cal_sP(l1, l2, mpk_file=b"./mpk"):
    """calculate s * P1 and s * P2 

        sP1 = \sum l1 
        sP2 = \sum l2

    Raise:
        OSError
    """
    if not os.path.exists(mpk_file):
        raise OSError("%s not exists" % mpk_file)
    
    assert(len(l1)==len(l2))
    cnt = len(l1)
    c_cnt = c_int(cnt)

    s1 = b'\x00'.join(l1)
    s2 = b'\x00'.join(l2)
    c_in = b'\x00'.join([s1, s2])

    lib_ibe = CDLL(LIBIBE_PATH)
    cal = lib_ibe.SS_cal_sP_py
    cal.argtypes = [PCHAR, c_int, c_char_p]
    cal.restype = PCHAR

    res = cal(c_in, c_cnt, mpk_file)

    o1 = []
    o2 = []

    for i in range(EC_POINT_LEN):
        o1.append(res[i])

    for i in range(POINT_LEN):
        o2.append(res[EC_POINT_LEN+i+1])

    o1 = b''.join(o1)    
    o2 = b''.join(o2)    

    return (o1, o2)

def SS_cal_sQ(l, mpk_file=b'./mpk'):
    """calculate s * P1 and s * P2 

        sQ = \sum l 

    Raise:
        OSError
    """
    if not os.path.exists(mpk_file):
        raise OSError("%s not exists" % mpk_file)
    
    cnt = len(l)
    c_cnt = c_int(cnt)

    c_in = b'\x00'.join(l)

    lib_ibe = CDLL(LIBIBE_PATH)
    cal = lib_ibe.SS_cal_sQ_py
    cal.argtypes = [PCHAR, c_int, c_char_p]
    cal.restype = PCHAR

    res = cal(c_in, c_cnt, mpk_file)

    ret = []

    for i in range(EC_POINT_LEN):
        ret.append(res[i])

    ret = b''.join(ret)    

    return ret

def SS_cal_xP(x, mpk_file=b"./mpk"):
    """calculate x * P1 and x * P2 

    Args:
        x: BIGNUM byte string

    Raise:
        OSError
    """
    if not os.path.exists(mpk_file):
        raise OSError("%s not exists" % mpk_file)

    lib_ibe = CDLL(LIBIBE_PATH)
    cal = lib_ibe.SS_cal_xP_py
    cal.argtypes = [c_char_p, c_char_p]
    cal.restype = PCHAR

    res = cal(x, mpk_file)
    ret = []
    for i in range(EC_POINT_LEN+1+129):
        ret.append(res[i])

    return b''.join(ret)
def SS_cal_xQ(x, user_id=b'', mpk_file=b"./mpk"):
    # TODO(wrk)
    """calculate x * Q_{id} 

    Args:
        x: BIGNUM byte string
        user_id: user_id

    Raise:
        OSError
    """
    if not os.path.exists(mpk_file):
        raise OSError("%s not exists" % mpk_file)
    
    point = SS_id2point(user_id, mpk_file=mpk_file)

    lib_ibe = CDLL(LIBIBE_PATH)
    cal = lib_ibe.SS_cal_xQ_py
    # share, point, mpk_file
    cal.argtypes = [c_char_p, c_char_p, c_char_p]
    cal.restype = PCHAR

    res = cal(x, point, mpk_file)
    ret = []
    for i in range(EC_POINT_LEN):
        ret.append(res[i])

    return b''.join(ret)

def SS_id2num(user_id, mpk_file=b"./mpk"):
    """generate a bignum from the user_id 

    Args:
        user_id: byte string 
        mpk_file: byte string

    Return:
        bignum, in byte string

    Raise:
        OSError if mpk_file not exists
    """
    if not os.path.exists(mpk_file):
        raise OSError("%s does not exist" % mpk_file)
    
    lib_ibe = CDLL(LIBIBE_PATH)
    id2num = lib_ibe.SS_id2num_py
    id2num.argtypes = ([c_char_p, c_int, c_char_p])
    id2num.restype = (PCHAR)

    res = id2num(user_id, len(user_id), mpk_file)
    ret = []
    for i in range(BN_HEX_SIZE):
        ret.append(res[i])
    return b''.join(ret)

def SS_id2point(user_id, mpk_file=b"./mpk"):
    """generate a bignum from the user_id 

    Args:
        user_id: byte string 
        mpk_file: byte string

    Return:
        EC_POINT, in byte string

    Raise:
        OSError if mpk_file not exists
    """
    if not os.path.exists(mpk_file):
        raise OSError("%s does not exist" % mpk_file)
    
    lib_ibe = CDLL(LIBIBE_PATH)
    id2num = lib_ibe.SS_id2point_py
    id2num.argtypes = ([c_char_p, c_int, c_char_p])
    id2num.restype = (PCHAR)

    res = id2num(user_id, len(user_id), mpk_file)
    ret = []
    for i in range(EC_POINT_LEN):
        ret.append(res[i])
    return b''.join(ret)


def SS_new_rand_poly(co_cnt):
    """generate a new polynomial

    Args:
        co_cnt: the number of coefficient, must be larger than 1
    
    Return:
        byte string representing a polynomial if success
    
    Raise:
        ValueError if co_cnt is not larger than 1
    """

    if co_cnt <= 1:
        raise ValueError("The least order of polynomail is 2")

    lib_ibe = CDLL(LIBIBE_PATH)
    new_poly = lib_ibe.SS_new_rand_poly_py
    new_poly.argtypes = ([c_int])
    new_poly.restype = (PCHAR)
    res = new_poly(co_cnt)
    
    # read all the values in a polynomial which are separated by '\0'
    # replace '\0's with '\n'
    ret = []
    sz = co_cnt * BN_HEX_SIZE
    for i in range(sz):
        ret.append(res[i])
    
    ret = b''.join(ret)
    return ret

def SS_output_sP(sP, mpk_file=b"./mpk"):
    sP1, sP2 = sP 
    lib_ibe = CDLL(LIBIBE_PATH)
    store = lib_ibe.SS_output_sP_py

    # param1: in sP1 + '\x00' + sP2 + '\x00'
    # param2: mpk_file
    store.argtypes = [PCHAR, c_char_p]
    store.restype = c_int
    # the third item can be any non-empty byte string
    # it is used to assure the input string is passed 
    # to the function exactly
    c_in = b"\x00".join([sP1, sP2, b"end"])
    res = store(c_in, mpk_file)

def SS_output_sQ(sQ, user=None, mode="global"):
    """
    Args:
        - mode : global/local
    """
    if not user:
        raise InitError("output sQ cannot be invoked without a user")
    
    c_id = user.id 
    c_id_len = len(c_id)
    c_id_len = c_int(c_id_len)
    if mode=="global":
        c_mpk_file = user.global_mpk_file
        c_sk_file = user.global_sk_file
    elif mode=="local":
        c_mpk_file = user.local_mpk_file 
        c_sk_file = user.local_sk_file 
    else:
        raise InitError()

    lib_ibe = CDLL(LIBIBE_PATH)
    store = lib_ibe.SS_output_sQ_py

    store.argtypes = [PCHAR, c_char_p, c_int, c_char_p, c_char_p]
    store.restype = c_int
    c_in = sQ + b"\x00"
    res = store(c_in, c_id, c_id_len, c_mpk_file, c_sk_file)

def SS_poly_apply(poly, co_cnt, bn):
    """apply a number to the polynomial

    Args:
        poly: byte string
        co_cnt:
        bn: byte string 
    
    Return:
        the result f(x), as a byte string 
    
    Raise:
        ValueError if co_cnt is not larger than 1
        ValueError if poly or bn is None
    """
    if not poly or not bn:
        raise ValueError("the polynomial and bn cannot be None")    
    if co_cnt <= 1:
        raise ValueError("The least order of polynomail is 2")

    lib_ibe = CDLL(LIBIBE_PATH)
    apply = lib_ibe.SS_poly_apply_py
    apply.argtypes = ([PCHAR, c_int, PCHAR])
    apply.restype = (c_char_p)
    res = apply(poly, co_cnt, bn)
    return res

class InitTest(object):

    def __init__(self, co_cnt=2):
        self.co_cnt = co_cnt
        self.poly = None
    
    def test_new(self):
        poly = SS_new_rand_poly(self.co_cnt)
        self.poly = poly

    def test_apply(self):
        bn = b'1'
        bn += b''*64
        res = SS_poly_apply(self.poly, self.co_cnt, bn)

    def test_id2num(self):
        res = SS_id2num(b"Client")
        print(res)

    def test_all(self):
        self.test_new()
        self.test_apply()
        self.test_id2num()

class InitError(Exception):
    def __init__(self, err='Error in Init Module'):
        Exception.__init__(self, err)


def main():
    initTest = InitTest()
    initTest.test_all()

if __name__ == "__main__":
    main()