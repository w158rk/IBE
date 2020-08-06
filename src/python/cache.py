#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    : cache.py
@Time    : 2020/08/06 20:29:15
@Author  : Ruikai Wang
@Contact : wrk15835@gmail.com
@Version : 0.1
@Desc    : functions used for certificate cache 
'''

from utils import bytes2str, str2bytes
# import csv
from threading import Timer
from base64 import b64encode, b64decode


class CertCache:
    def __init__(self, filename="./certs"):
        self.cert_set = set()
        self.filename = filename
        self._empty = True

    def insert_certs(self, dgst_list=[]):
        """
        Args:
            dgst_list: the hash value of a certificate
                        every dgst is a byte string
        """
        for dgst in dgst_list:
            self.cert_set.add(dgst)

    def input_cache(self):
        ret = None
        with open(self.filename, "r") as f:
            certs = [str2bytes(b64decode(cert)) for cert in f]
            ret = set(certs)
        self._empty = False
        return ret            

    def output_cache(self):
        cert_list = list(self.cert_set)
        cert_list = [bytes2str(b64encode(cert)) for cert in cert_list]
        cert_list.sort()
        with open(self.filename, "w") as f:
            f.write('\n'.join(cert_list))
        
    def empty(self):
        return self._empty

    def run(self, interval=5):
        """
        output per 5 seconds by default
        """
        sTimer = Timer(3, self.output_cache)
        sTimer.start()
