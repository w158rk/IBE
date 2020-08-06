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
import csv


class CertCache:
    def __init__(self, filename="./certs"):
        self.cert_set = set()
        self.filename = filename

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
            reader = csv.reader(f)
            certs = [str2bytes(cert) for cert in reader]
            ret = set(certs)
        return ret            

    def output_cache(self):
        cert_list = list(self.cert_set)
        cert_list.sort()
        cert_list = [bytes2str(cert) for cert in cert_list]
        with open(self.filename, "w") as f:
            writer = csv.writer(f)
            writer.writerows(cert_list)
        

    

