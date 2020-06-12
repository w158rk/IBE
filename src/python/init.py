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
    print(id_list)

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
    print(res)

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

def main():
    initTest = InitTest()
    initTest.test_all()

if __name__ == "__main__":
    main()