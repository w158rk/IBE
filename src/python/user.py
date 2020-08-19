#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

'''
@File    :   user.py
@Time    :   2020/05/17 16:23:16
@Author  :   Ruikai Wang
@Version :   1.0
@Contact :   wrk15835@gmail.com
@License :   Copyright (c) 2020 Ruikai Wang
@Desc    :   Class for presenting a user in the network
'''

from action import Action
from constant import *
from init import *
from crypto_c_interface import *
from packet import Packet
from client import Client
from server import Server
from utils import str2bytes
from auth import Certificate
from base64 import b64decode, b64encode
from cache import CertCache

import socket
import threading
import time
import json
import string
from os import urandom
# from random import sample
# import random

_bytes_attributes = ["id", "addr",
                     "global_mpk_file",
                     "global_sk_file",
                     "admin_mpk_file",
                     "admin_msk_file",
                     "admin_sk_file",
                     "local_sk_file",
                     "local_mpk_file"]


class User(object):
    """class presenting users in the network

    Attributes:
        id: the identification
        addr: the IP address
        port: the port on which the user is running

    """

    def __init__(self, user_id=b"", addr="", port=0,
                 top_user_list=[], config_file=None):
        """
        Args:
            - top_user_list:
                a list of dicts which represent a user with keyset: (id, addr, port)
            - recv_list:
                only used when a server is invoked by the init process
        """
        # declare all the members
        # all the variables used should be declared
        # here for maintaining convenience
        self.top_user_list = top_user_list
        self.config_file = config_file
        self.id = user_id
        self.addr = addr
        self.port = port

        # from configuration
        self.log = b""
        self.global_mpk_file = b""
        self.global_sk_file = b""
        self.local_mpk_file = b""
        self.local_sk_file = b""
        self.admin_mpk_file = b""
        self.admin_msk_file = b""
        self.admin_sk_file = b""
        self.local_certificate_file = b""
        self.admin_certificate_file = b""
        self.cert = b""
        self.sm4_key = b""
        self.key = b""
        self.IOT_key = b""
        self.parent = None
        self.time = None
        self.certificate_cache = "./certs"

        # inner variables
        self.recv_lists = [set() for i in range(3)]
        self.sent_ack_cnts = [0, 0, 0]
        self.client = None
        self.server = None
        self.sym_key = b""

        # for init use
        self.is_in_init = False
        self.share = None
        self.sP = (None, None)

        if config_file:
            self.load_config_file()

        if self.top_user_list:
            top_user_list = []
            for user in self.top_user_list:
                if str2bytes(user["id"]) != self.id:
                    top_user_list.append(self.from_dict(user))
            self.top_user_list = top_user_list

        if self.parent:
            # convert the json object to the User object
            parent = self.parent
            parent = self.from_dict(parent)
            if not parent:
                raise UserError('Error in the configuration of parent')
            self.parent = parent

        # certificate cache
        # NOTE: cert_cache is an object, while certificate_cache is a filename
        # For the maintainance consideration, never use self.certificate_cache
        self.cert_cache = CertCache(filename=self.certificate_cache)
        self.cert_cache.run()

    @classmethod
    def from_dict(cls, user_dict):
        user = cls()
        for attr in user_dict:
            if attr in _bytes_attributes:
                user.__setattr__(attr, str2bytes(user_dict[attr]))
            else:
                user.__setattr__(attr, user_dict[attr])
        return user

    # instance functions

    def add_certs_in_cache(self, certs):
        self.cert_cache.insert_certs([sm3_hash(cert.to_bytes()) for cert in certs])

    def cal_share(self):
        """
        calculate the share with formula:

                share = (\sum f(x)) * l_x(0)
        """
        id_list = []
        id_list.append(self.id)
        for user in self.top_user_list:
            id_list.append(user.id)
        return SS_cal_share(self.recv_lists[0], id_list, mpk_file=self.global_mpk_file)

    def cal_sP(self):
        """
        calculate sP1 = \sum share * P1
        calculate sP2 = \sum share * P2
        """

        # l1 and l2 for list of sP1 and sP2
        l1 = []
        l2 = []
        for s in self.recv_lists[1]:
            assert(s[EC_POINT_LEN] == 124)
            assert(len(s) == EC_POINT_LEN + 1 + POINT_LEN)
            l1.append(s[:EC_POINT_LEN])
            l2.append(s[EC_POINT_LEN+1:])

        sP1, sP2 = SS_cal_sP(l1, l2, mpk_file=self.global_mpk_file)
        return (sP1, sP2)

    def cal_sQ(self):
        """
        calculate sQ = \sum share * Q
        """
        l = []
        for s in self.recv_lists[2]:
            assert(len(s) == EC_POINT_LEN)
            l.append(s)
        return SS_cal_sQ(l, mpk_file=self.global_mpk_file)

    def cal_shareP(self):
        return SS_cal_xP(self.share, mpk_file=self.global_mpk_file)

    def cal_shareQ(self, user=None):
        if not user:
            user = self
        return SS_cal_xQ(self.share, user_id=user.id, mpk_file=self.global_mpk_file)

    def check_mpk(self, mpk=b"", certs=[]):
        """
        check the validation of a master public key, return True if valid
        """
        # TODO(wxy): change the logic of this function if cache is used
        # Visit all the certs in the list
        # NOTE: from up to down / from down to up
        # down-to-up in current version

        # check: mpk = the mpk in the first certificate

        start = time.time()

        assert mpk == certs[0].payload.mpk

        # check the validation of the links
        for index, cert in enumerate(certs[:-1]):

            next_cert = certs[index+1]
            if not cert.payload.iss == next_cert.payload.aud:
                print("issError")
                return False

            given_dgst = cert.payload.parent.hash
            cal_dgst = sm3_hash(next_cert.to_bytes())
            if not given_dgst == cal_dgst:
                print("hashError")
                return False

        # check the validation of all the signatures
        for index, cert in enumerate(certs[:-1]):
            next_cert = certs[index+1]
            sig = cert.sig.sig
            iss = cert.payload.iss
            mpk = next_cert.payload.mpk
            top = False
            if next_cert.payload.top_types == "top":
                top = True
            if not cert.verify(next_cert.payload.mpk, top):
                print("verifyError")
                return False

        end = time.time()
        print("sign verify: ", end-start)

        return True

    def generate_sym_key(self):
        """
        just generate 256-bit byte string
        """
        # lint = random.sample(range(256), 32)
        lint = urandom(16)
        # lchar = [chr(a) for a in lint]
        # lchar = ''.join(lchar)
        # ret = str2bytes(lchar)
        # self.sym_key = ret
        return lint

    def get_sk_file_from_mode(self, mode):
        sk_file = ""
        if mode == "global":
            sk_file = self.global_sk_file
        elif mode == "admin":
            sk_file = self.admin_sk_file
        elif mode == "local":
            sk_file = self.local_sk_file
        else:
            raise UserError()
        return sk_file

    def sm4_enc(self, key=b"", m=b""):
        return sm4_enc(key, m)

    def sm4_dec(self, key=b"", c=b""):
        return sm4_dec(key, c)

    def ibe_setup(self, mode="global"):
        """
        Args:
            mode: choose in ["admin", "global"]
        """
        mpk_file = self.global_mpk_file
        nouse_suffix = b".nouse"
        len_suffix = b".len"
        if mode == "global":
            ibe_setup(mpk_file, mpk_file+nouse_suffix, mpk_file+len_suffix, mpk_file+nouse_suffix+len_suffix)
        if mode == "admin":
            mpk_file = self.admin_mpk_file
            msk_file = self.admin_msk_file
            assert mpk_file
            assert msk_file
            ibe_setup(mpk_file, msk_file, mpk_file+len_suffix, msk_file+len_suffix)

    def ibe_extract(self, mode="", c_id=b""):
        assert mode == "admin"
        msk_file = self.admin_msk_file
        with open(msk_file, "rb") as f:
            msk = f.read()

        return ibe_extract(msk, c_id)

    def ibe_encrypt(self, mode="", m=b"", user_id=b"", filename="", mpk=b""):
        """
        mode is in ["global", "admin", "local", "comm"]
        """
        mpk_file = b""
        if mode == "global":
            mpk_file = self.global_mpk_file
        elif mode == "admin":
            mpk_file = self.admin_mpk_file
        elif mode == "local":
            mpk_file = self.local_mpk_file
        elif mode == "comm":
            return ibe_encrypt(m, mpk, user_id)
        else:
            raise UserError()
        with open(mpk_file, "rb") as f:
            mpk = f.read()
        return ibe_encrypt(m, mpk, user_id)

    def ibe_decrypt(self, mode="", c=b""):
        """
        mode is in ["global", "admin", "local"]
        """
        sk_file = b''
        if mode == "global":
            sk_file = self.global_sk_file
        elif mode == "admin":
            sk_file = self.admin_sk_file
        elif mode == "local":
            sk_file = self.local_sk_file
        else:
            raise UserError()

        sk = ibe_read_from_file(sk_file)
        return ibe_decrypt(c, sk)

    def ibe_sign(self, mode="", m=b""):
        """
        mode is in ["global", "admin", "local"]
        """
        sk_file = b''
        if mode == "global":
            sk_file = self.global_sk_file
        elif mode == "admin":
            sk_file = self.admin_sk_file
        elif mode == "local":
            sk_file = self.local_sk_file
        else:
            raise UserError()
        with open(sk_file, "rb") as f:
            sk = f.read()
        return ibe_sign(m, sk)

    def ibe_verify(self, mode="", m=b"", sm=b"", user_id=b"", filename="", mpk=b""):
        """
        mode is in ["global", "admin", "local", "comm"]
        """
        mpk_file = b""
        if mode == "global":
            mpk_file = self.global_mpk_file
        elif mode == "admin":
            mpk_file = self.admin_mpk_file
        elif mode == "local":
            mpk_file = self.local_mpk_file
        elif mode == "comm":
            return ibe_verify(m, sm, mpk, user_id)
        else:
            raise UserError()
        with open(mpk_file, "rb") as f:
            mpk = f.read()
        return ibe_verify(m, sm, mpk, user_id)

    def sig_verify(self, client_id=b"", sig=b""):

        # time_start=time.time()

        s = Certificate()
        s = s.from_bytes(sig)

        s_iss = s.payload.iss
        s_aud = s.payload.aud
        s_mpk = s.payload.mpk
        s_parent = s.payload.parent

        if s_aud.encode() != client_id:
            print("ClientIDError!")
            print(s_aud)
            print(client_id)
            return False
        else:
            pass

        if s_parent == "null":
            # the inner packet
            global_mpk = self.input_mpk(mode="global")

            if global_mpk != s_mpk or s_iss != s_aud:
                print("InnerVerifyError!")
                return False
            else:
                pass

        else:
            self.sig_verify(s_iss.encode(), s_parent)

        s_sig = s.sig.sig

        header = s.header.to_bytes()
        payload = s.payload.to_bytes()
        m = b".".join([header, payload])

        if not ibe_verify(m, s_sig, s_mpk, client_id):
            print("SignError!")
            return False
        else:
            pass

        # time_end=time.time()
        # print('totally cost',time_end-time_start)

        return True

    def input_certs(self):
        """
        DISTINGUISH this from input_cert, this is for input
        certs in the cache
        """
        pass

    def input_all_admin_certs(self):
        cert_file = self.admin_certificate_file
        ret = []
        while True:
            with open(cert_file, "r") as f:
                json_str = f.read()
                cert = Certificate.from_json(json_str)
                ret.append(cert)
                if not cert.payload.parent:
                    break
                cert_file = cert.payload.parent.filename
        return ret

    def input_all_local_certs(self):
        cert_file = self.local_certificate_file
        ret = []
        while True:
            with open(cert_file, "r") as f:
                json_str = f.read()
                cert = Certificate.from_json(json_str)
                ret.append(cert)
                if not cert.payload.parent:
                    break
                cert_file = cert.payload.parent.filename
        return ret

    def input_cert(self, filename=None):
        """
        This is for input the certificate of this user
        """
        if not filename:
            filename = self.admin_certificate_file
        with open(filename, "r") as f:
            return f.read()

    def input_mpk(self, mode=""):
        if mode == "global":
            mpk_file = self.global_mpk_file
        elif mode == "admin":
            mpk_file = self.admin_mpk_file
        elif mode == "local":
            mpk_file = self.local_mpk_file
        else:
            raise UserError()

        return ibe_read_from_file(mpk_file)

    def input_sk(self, mode=""):
        return ibe_read_from_file(self.get_sk_file_from_mode(mode))

    def load_config_file(self):
        config = None
        with open(self.config_file, "r", encoding="utf-8") as f:
            config = json.load(f)

        for attr in config:
            if not config[attr]:
                continue
            if attr in _bytes_attributes:
                self.__setattr__(attr, str2bytes(config[attr]))
            else:
                self.__setattr__(attr, config[attr])

        try:
            top_user_list = self.top_user_list
            with open(top_user_list, "r", encoding="utf-8") as f:
                top_user_list = json.load(f)
            self.top_user_list = top_user_list
        except AttributeError:
            pass

    def output_cert(self, cert="", cert_file="", ctype=""):
        """
        output the cert of this user, DISTINGUISH this from output_certs!
        """
        if not cert_file:
            if ctype == "local":
                cert_file = self.local_certificate_file
            elif ctype == "admin":
                cert_file = self.admin_certificate_file
        assert cert_file
        with open(cert_file, "w") as f:
            f.write(cert)

    def output_certs(self, certs=[]):
        """
        output certs in the cache
        """
        self.cert_cache.output_cache()

    def output_sk(self, sk, mode="global"):
        sk_file = self.get_sk_file_from_mode(mode)
        ibe_write_to_file(sk, sk_file)

    def output_sP(self, sP, mpk_file=b"./mpk"):
        SS_output_sP(sP, mpk_file=mpk_file)

    def output_sQ(self, sQ):
        SS_output_sQ(sQ, user=self)

    def run_gen_sys(self):
        print("generate the system")
        print("ibe_setup")
        self.ibe_setup(mode="admin")
        sk = self.ibe_extract(mode="admin", c_id=self.id)
        self.output_sk(sk, mode="admin")

    def run_init(self, with_val=None, is_listening=False):
        """
        setup the HIBE system with secret sharing
        """
        # TODO(wrk): this function is too long
        if with_val:
            self.recv_lists[0].add(with_val)

        if self.is_in_init:
            # if is in init, just add the val into the list
            return

        if not os.path.exists(self.global_mpk_file):
            self.ibe_setup("global")

        print("begin running initialization")
        self.is_in_init = True

        # at the beginning, we should set up a server for
        # receiving the desired packets
        print("start server")
        if not is_listening:
            if not self.server:
                self.server = Server(self)

            t = threading.Thread(target=self.server.run)
            t.start()

        # setup the client
        if not self.client:
            self.client = Client(self)

        time.sleep(2)               # set some time for the server starting

        top_user_list = self.top_user_list
        if not top_user_list:
            raise UserError("The init cannot be invoked without the top users")

        # sz + 1 == the number of top users
        sz = len(self.top_user_list)
        co_cnt = sz + 1

        # generate a polynomial at first
        print("round one")
        poly = SS_new_rand_poly(co_cnt)

        # add f_i(x_i) into the list
        bn = SS_id2num(self.id, mpk_file=self.global_mpk_file)
        bn = SS_poly_apply(poly, co_cnt, bn)
        self.recv_lists[0].add(bn)

        # round one
        # send the values while receiving
        while len(self.recv_lists[0]) < co_cnt or self.sent_ack_cnts[0] < sz:
            for user in top_user_list:
                packet = Packet.make_init_1(poly, co_cnt, user.id, mpk_file=self.global_mpk_file)
                data = packet.to_bytes()
                self.send(user, data)

            time.sleep(2)
        # now we have all the parts for our share
        # it's time to calculate the share with formula:
        #
        # share = (\sum f(x)) * l_x(0)
        share = self.cal_share()
        self.share = share

        # round 1 finished, in round 2, shares will be sent among users
        # first, add the share_i * P1 & share_i * P2 in the list
        print("round 2")
        point = self.cal_shareP()
        self.recv_lists[1].add(point)

        while len(self.recv_lists[1]) < co_cnt or self.sent_ack_cnts[1] < sz:
            for user in top_user_list:
                packet = Packet.make_init_2(point)
                data = packet.to_bytes()
                self.send(user, data)

            time.sleep(2)

        sP = self.cal_sP()              # a tuple
        self.sP = sP
        self.output_sP(sP, mpk_file=self.global_mpk_file)

        # the public master key is stored in global_mpk_file
        # now it's time to calculate the private key for
        # the top users
        round_index = 2
        point = self.cal_shareQ()
        self.recv_lists[round_index].add(point)

        print("round 3")
        while len(self.recv_lists[round_index]) < co_cnt or self.sent_ack_cnts[round_index] < sz:
            for user in top_user_list:
                point = self.cal_shareQ(user=user)
                packet = Packet.make_init_3(point, mpk_file=self.global_mpk_file)
                data = packet.to_bytes()
                self.send(user, data)

            time.sleep(2)

        # calculate sQ
        sQ = self.cal_sQ()
        self.sQ = sQ
        self.output_sQ(sQ)

        if not self.parent and not os.path.exists(self.local_certificate_file):
            # top user without certificate file
            self.server.run_gen_local_auth()

        # generate the admin domain after the initialization
        if os.path.exists(self.admin_mpk_file) and os.path.exists(self.admin_msk_file) and os.path.exists(self.admin_sk_file):
            pass        # do nothing
        else:
            self.run_gen_sys()
            self.server.run_gen_admin_auth()

        # clear the related data
        self.is_in_init = False
        self.sent_ack_cnts = [0, 0, 0]
        for s in self.recv_lists:
            s.clear()

        print("The initialization has finished")

    def send(self, user, data):
        addr = user.addr
        port = user.port

        action = Action()
        action.type = Action.ActionType.SEND
        action.payload = [data]

        t = threading.Thread(target=self.client.run_send, args=(addr, port, action))
        t.start()


class UserError(Exception):
    def __init__(self, err='Error in Client Module'):
        Exception.__init__(self, err)
