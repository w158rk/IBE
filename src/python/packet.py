#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

'''
@File    :   packet.py
@Time    :   2020/06/08 08:36:03
@Author  :   Ruikai Wang
@Version :   1.0
@Contact :   wrk15835@gmail.com
@License :   Copyright (c) 2020 Ruikai Wang
@Desc    :   Packet
'''

from enum import Enum
from init import SS_poly_apply, SS_id2num
from utils import str2bytes, int2bytes, bytes2int

import os
from base64 import b64encode, b64decode


class Packet(object):
    """class representing a packet

    Attributes:
        type:
        lens:       length of all the parts
        vals:       values of all the parts
    """

    class PacketType(Enum):
        INIT_R1 = 1       # for the first round of initialization
        INIT_R1_ACK = 2
        INIT_R2 = 3       # for the second round of initialization
        INIT_R2_ACK = 4
        INIT_R3 = 5       # for the third round of initialization
        INIT_R3_ACK = 6

        MPK_REQUEST = 10
        MPK_RESPOND = 11

        SK_REQUEST_KEY_PLAIN = 20
        SK_REQUEST_KEY_SEC = 21
        SK_RESPOND_KEY_PLAIN = 22
        SK_RESPOND_KEY_SEC = 23
        SK_KEY_ACK = 24
        SK_KEY_ACK_ACK = 25

        COMM_CLIENT_HELLO = 30
        COMM_SERVER_HELLO = 31
        COMM_CLIENT_FINISH = 32
        COMM_SERVER_FINISH = 33
        COMM_REFUSE = 34

        KEY_REQUEST_PLAIN = 40
        KEY_REQUEST_SEC = 41
        KEY_RESPOND = 42

        QUIT_REQUEST_PLAIN = 50
        QUIT_REQUEST_SEC = 51

        DOMAIN_REQUEST_PLAIN = 60
        DOMAIN_REQUEST_SEC = 61
        DOMAIN_SUBMIT_SEC = 62
        DOMAIN_FINISH = 63
        DOMAIN_UPDATE_REQUEST_PLAIN = 64
        DOMAIN_UPDATE_REQUEST_SEC = 65
        DOMAIN_UPDATE_RESPOND_PLAIN = 66
        DOMAIN_UPDATE_RESPOND_SEC = 67

    def __init__(self, pack_type=PacketType.INIT_R1, lens=[], vals=[]):
        self.type = pack_type
        self.lens = lens
        self.vals = vals

    @classmethod
    def from_bytes(cls, bstr):
        ret = Packet()

        header, lens, vals = bstr.split(b'|')
        bstr_header = b64decode(header)
        bstr_lens = b64decode(lens)
        bstr_vals = b64decode(vals)

        index = 0
        pack_type = bytes2int(bstr_header[index: index+2])
        pack_type = cls.PacketType(pack_type)
        ret.type = pack_type

        index += 2
        sz = bytes2int(bstr_header[index: index+2])

        # read the lens
        index = 0
        lens = []
        for _ in range(sz):
            lens.append(bytes2int(bstr_lens[index: index+2]))
            index += 2
        ret.lens = lens

        # read the values
        index = 0
        vals = []
        for l in lens:
            vals.append(bstr_vals[index: index+l])
            index += l
        ret.vals = vals

        return ret

    @classmethod
    def make_init_1(cls, poly, co_cnt, user_id, mpk_file=b"./mpk"):
        # send the f(h(ID))
        packet = Packet()
        packet.type = cls.PacketType.INIT_R1

        if type(user_id) == str:
            user_id = str2bytes(user_id)
        bn = SS_id2num(user_id, mpk_file)
        bn = SS_poly_apply(poly, co_cnt, bn)
        lens = [len(bn)]
        vals = [bn]

        packet.lens = lens
        packet.vals = vals

        return packet

    @classmethod
    def make_init_2(cls, point):
        """
        As the point is calculated in the user module, here we just arrange the
        packet without calculate anything
        """

        packet = Packet()
        packet.type = cls.PacketType.INIT_R2

        lens = [len(point)]
        vals = [point]

        packet.lens = lens
        packet.vals = vals

        return packet

    @classmethod
    def make_init_3(cls, point):
        """
        the point is calculated in the user module, just add it into a packet
        """

        packet = Packet()
        packet.type = cls.PacketType.INIT_R3

        lens = [len(point)]
        vals = [point]

        packet.lens = lens
        packet.vals = vals

        return packet

    #####################################################################
    # domain related
    #####################################################################

    @classmethod
    def make_domain_request_plain(cls, user_id, mpk):
        """
        make the packet with the id and the new domain mpk
        """

        packet = Packet()
        packet.type = cls.PacketType.DOMAIN_REQUEST_PLAIN

        mpk = b64encode(mpk)
        lens = [len(user_id), len(mpk)]
        vals = [user_id, mpk]

        packet.lens = lens
        packet.vals = vals

        return packet

    @classmethod
    def make_domain_request_sec(cls, payload, sig):
        """
        pack the plain payload and the signature
        """


        packet = Packet()
        packet.type = cls.PacketType.DOMAIN_REQUEST_SEC

        lens = [len(payload), len(sig)]
        vals = [payload, sig]

        packet.lens = lens
        packet.vals = vals

        return packet

    @classmethod
    def make_domain_submit_sec(cls, payload, sig):
        packet = cls.make_domain_request_sec(payload, sig)
        packet.type = cls.PacketType.DOMAIN_SUBMIT_SEC
        return packet

    @classmethod 
    def make_domain_finish(cls):
        packet = cls()
        packet.type = cls.PacketType.DOMAIN_FINISH 
        return packet

    @classmethod
    def make_domain_update_plain(cls, user_id, old_mpk, new_mpk):
        packet = cls()
        packet.type = cls.PacketType.DOMAIN_UPDATE_REQUEST_PLAIN
        lens = [len(user_id), len(old_mpk), len(new_mpk)]
        vals = [user_id, old_mpk, new_mpk]

        packet.lens = lens
        packet.vals = vals

        return packet

    @classmethod
    def make_domain_update_sec(cls, payload, sig):
        packet = cls.make_domain_request_sec(payload, sig)
        packet.type = cls.PacketType.DOMAIN_UPDATE_REQUEST_SEC
        return packet


    #=====================================================================#

    @classmethod
    def make_mpk_request(cls, user_id):
        """
        plaintext, with only the user_id
        """

        packet = Packet()
        packet.type = cls.PacketType.MPK_REQUEST

        lens = [len(user_id)]
        vals = [user_id]

        packet.lens = lens
        packet.vals = vals

        return packet

    @classmethod
    def make_mpk_respond(cls, mpkglobal_file="./mpk-global.conf", mpk_file="./mpk_file"):
        """
        read the content of the given files, TODO(wxy): certificate left
        """

        assert os.path.exists(mpk_file)
        assert os.path.exists(mpkglobal_file)

        mpk = b""
        with open(mpk_file, "rb") as f:
            mpk = f.read()

        global_mpk = b""
        with open(mpkglobal_file, "rb") as f:
            global_mpk = f.read()

        packet = Packet()
        packet.type = cls.PacketType.MPK_RESPOND

        lens = [len(global_mpk), len(mpk)]
        vals = [global_mpk, mpk]

        packet.lens = lens
        packet.vals = vals

        return packet

    @classmethod
    def make_sk_request_key_plain(cls, key=b'', user_id=b'', secret=b'secret'):
        """
        make a packet with a random key
        """

        assert key
        assert user_id

        packet = Packet()
        packet.type = cls.PacketType.SK_REQUEST_KEY_PLAIN

        lens = [len(key), len(user_id), len(secret)]
        vals = [key, user_id, secret]

        packet.lens = lens
        packet.vals = vals

        return packet

    @classmethod
    def make_sk_request_key_sec(cls, cipher=b'', sig=b"no"):
        """
        just make the cipher and the sig in the packet
        """
        assert cipher

        packet = Packet()
        packet.type = cls.PacketType.SK_REQUEST_KEY_SEC

        lens = [len(cipher), len(sig)]
        vals = [cipher, sig]

        packet.lens = lens
        packet.vals = vals

        return packet

    @classmethod
    def make_sk_respond_key_plain(cls, user_sk=b'', user_id=b'', server_id=b''):
        """
        make the packet with client's sk and sk length
        """
        assert user_sk
        assert user_id 
        assert server_id

        packet = Packet()
        packet.type = cls.PacketType.SK_RESPOND_KEY_PLAIN

        lens = [len(user_id), len(server_id), len(user_sk)]
        vals = [user_id, server_id, user_sk]

        packet.lens = lens
        packet.vals = vals

        return packet

    @classmethod
    def make_sk_respond_key_sec(cls, cipher=b''):
        """
        just make the cipher in the packet
        """
        assert cipher

        packet = Packet()
        packet.type = cls.PacketType.SK_RESPOND_KEY_SEC

        lens = [len(cipher)]
        vals = [cipher]

        packet.lens = lens
        packet.vals = vals

        return packet

    #==================================================================
    # comm
    #==================================================================

    @classmethod
    def make_comm_client_hello(cls, des_id=b'', src_id=b'', mpk=b'', key_mode=b"", certs=[]):
        """
        for the first communication init
        """
        assert des_id
        assert src_id
        assert mpk          # the mpk might be eliminated in the cloud
        assert certs
        assert key_mode

        packet = Packet()
        packet.type = cls.PacketType.COMM_CLIENT_HELLO

        lens = [len(des_id), len(src_id), len(mpk), len(key_mode)]
        vals = [des_id, src_id, mpk, key_mode]

        for cert in certs:
            lens.append(len(cert))
            vals.append(cert)

        packet.lens = lens
        packet.vals = vals

        return packet

    @classmethod
    def make_comm_server_hello(cls, mode=b'', des_id=b'', src_id=b'', mpk=b'', certs=[], key_mode=b''):
        """
        for the first communication init respond

        mode(?):
            1: same domin
            2: cross domin
            3: comm with father node
        """
        assert des_id
        assert src_id
        assert mpk
        assert certs
        assert key_mode

        packet = Packet()
        packet.type = cls.PacketType.COMM_SERVER_HELLO

        lens = [len(mode), len(des_id), len(src_id), len(mpk), len(key_mode)]
        vals = [mode, des_id, src_id, mpk, key_mode]

        for cert in certs:
            lens.append(len(cert))
            vals.append(cert)

        packet.lens = lens
        packet.vals = vals

        return packet
    #==================================================================


    @classmethod
    def make_key_request_plain(cls, des_id=b'', src_id=b'', key=b'', key_mode=b''):
        """
        make the packet with the key
        """
        assert des_id
        assert src_id
        assert key
        assert key_mode

        packet = Packet()
        packet.type = cls.PacketType.KEY_REQUEST_PLAIN

        lens = [len(des_id), len(src_id), len(key), len(key_mode)]
        vals = [des_id, src_id, key, key_mode]

        packet.lens = lens
        packet.vals = vals

        return packet

    @classmethod
    def make_key_request_sec(cls, mode=b"comm", cipher=b'', sign=b''):
        """
        just make the cipher in the packet
        """
        assert mode in {b"parent", b"comm", b"sibling"}
        assert cipher
        assert sign

        packet = Packet()
        packet.type = cls.PacketType.KEY_REQUEST_SEC

        lens = [len(mode), len(cipher), len(sign)]
        vals = [mode, cipher, sign]

        packet.lens = lens
        packet.vals = vals

        return packet

    @classmethod
    def make_key_respond(cls, des_id=b'', src_id=b'', m=b'', key_mode=b''):
        """
        make the packet with the "ACK"
        """
        assert des_id
        assert src_id
        assert m
        assert key_mode

        packet = Packet()
        packet.type = cls.PacketType.KEY_RESPOND

        lens = [len(des_id), len(src_id), len(m), len(key_mode)]
        vals = [des_id, src_id, m, key_mode]

        packet.lens = lens
        packet.vals = vals

        return packet

    @classmethod
    def quit_request_plain(cls, client_id=b'', m=b''):
        """
        make the packet with the client_id and message "quit"
        """
        assert client_id
        assert m

        packet = Packet()
        packet.type = cls.PacketType.QUIT_REQUEST_PLAIN

        lens = [len(client_id), len(m)]
        vals = [client_id, m]

        packet.lens = lens
        packet.vals = vals

        return packet

    @classmethod
    def quit_request_sec(cls, cipher=b'', sign=b''):
        """
        make the packet with the cipher and the sign
        """
        assert cipher
        assert sign

        packet = Packet()
        packet.type = cls.PacketType.QUIT_REQUEST_SEC

        lens = [len(cipher), len(sign)]
        vals = [cipher, sign]

        packet.lens = lens
        packet.vals = vals

        return packet

    @classmethod
    def update_sk_plain(cls, sk=b''):
        """
        make the packet with the update sk
        """
        assert sk

        packet = Packet()
        packet.type = cls.PacketType.UPDATE_SK_PLAIN

        lens = [len(sk)]
        vals = [sk]

        packet.lens = lens
        packet.vals = vals

        return packet

    @classmethod
    def gen_domain_request(cls, user_id=b'', key_mode=b'', key=b''):

        packet = Packet()
        packet.type = cls.PacketType.GEN_DOMAIN_REQUEST

        lens = [len(user_id), len(key_mode), len(key)]
        vals = [user_id, key_mode, key]

        packet.lens = lens
        packet.vals = vals

        return packet

    @classmethod
    def gen_domain_plain(cls, mpk=b'', msk=b'', sk=b''):

        packet = Packet()
        packet.type = cls.PacketType.GEN_DOMAIN_PLAIN

        lens = [len(mpk), len(msk), len(sk)]
        vals = [mpk, msk, sk]

        packet.lens = lens
        packet.vals = vals

        return packet

    @classmethod
    def gen_domain_sec(cls, cipher=b''):
        packet = Packet()
        packet.type = cls.PacketType.GEN_DOMAIN_SEC

        lens = [len(cipher)]
        vals = [cipher]

        packet.lens = lens
        packet.vals = vals

        return packet
    


    @classmethod
    def gen_domain_cert_requet(cls, user_id, user_mpk, father_id, father_sk):
        packet = Packet()
        packet.type = cls.PacketType.CERT_DOMAIN_REQUEST

        lens = [len(user_id), len(user_mpk), len(father_id), len(father_sk)]
        vals = [user_id, user_mpk, father_id, father_sk]

        packet.lens = lens
        packet.vals = vals

        return packet

    @classmethod
    def make_sec_request_init(cls, des_id=b'', src_id=b'', mpk=b'', certs=[]):
        assert des_id
        assert src_id
        assert mpk
        assert certs

        packet = Packet()
        packet.type = cls.PacketType.MAKE_SEC_REQUEST_INIT

        lens = [len(des_id), len(src_id), len(mpk)]
        vals = [des_id, src_id, mpk]

        for cert in certs:
            lens.append(len(cert))
            vals.append(cert)

        packet.lens = lens
        packet.vals = vals

        return packet

    @classmethod
    def make_sec_respond_init(cls, des_id=b'', src_id=b'', mpk=b'', certs=[]):
        assert des_id
        assert src_id
        assert mpk
        assert certs

        packet = Packet()
        packet.type = cls.PacketType.MAKE_SEC_RESPOND_INIT

        lens = [len(des_id), len(src_id), len(mpk)]
        vals = [des_id, src_id, mpk]

        for cert in certs:
            lens.append(len(cert))
            vals.append(cert)

        packet.lens = lens
        packet.vals = vals

        return packet

    @classmethod
    def make_sec_request(cls, cipher=b''):
        """
        just make the cipher in the packet
        """
        assert cipher

        packet = Packet()
        packet.type = cls.PacketType.MAKE_SEC_REQUEST

        lens = [len(cipher)]
        vals = [cipher]

        packet.lens = lens
        packet.vals = vals

        return packet

    # @classmethod
    # def make_sec_request(cls, user_id, mpk, cert, m):

    #     packet = Packet()
    #     packet.type = cls.PacketType.MAKE_SEC_REQUEST

    #     lens = [len(user_id), len(mpk), len(cert), len(m)]
    #     vals = [user_id, mpk, cert, m]

    #     packet.lens = lens
    #     packet.vals = vals

    #     return packet

    # @classmethod
    # def make_sec_respond(cls, cipher):

    #     packet = Packet()
    #     packet.type = cls.PacketType.MAKE_SEC_RESPOND

    #     lens = [len(cipher)]
    #     vals = [cipher]

    #     packet.lens = lens
    #     packet.vals = vals

    #     return packet

    @classmethod
    def make_dec_request(cls, sk, c):
        packet = Packet()
        packet.type = cls.PacketType.MAKE_DEC_REQUEST

        lens = [len(sk), len(c)]
        vals = [sk, c]

        packet.lens = lens
        packet.vals = vals

        return packet

    @classmethod
    def make_dec_respond(cls, m):
        packet = Packet()
        packet.type = cls.PacketType.MAKE_DEC_RESPOND

        lens = [len(m)]
        vals = [m]

        packet.lens = lens
        packet.vals = vals

        return packet


    @classmethod
    def make_sk_respond(cls, sk):
        packet = Packet()
        packet.type = cls.PacketType.MAKE_SK_RESPOND

        lens = [len(sk)]
        vals = [sk]

        packet.lens = lens
        packet.vals = vals

        return packet

    def to_bytes(self):
        """
        Raise:
            ValueError if the lengths of lens and vals differ
        """

        if len(self.lens) != len(self.vals):
            raise ValueError("the lengths of lens and vals differ")

        header = []
        header.append(self.type.value.to_bytes(2, 'little'))
        header.append(len(self.lens).to_bytes(2, 'little'))
        header = b''.join(header)
        header = b64encode(header)

        lens = [l.to_bytes(2, 'little') for l in self.lens]
        lens = b''.join(lens)
        lens = b64encode(lens)

        vals = b''.join(self.vals)
        vals = b64encode(vals)
        return b'|'.join([header, lens, vals])


class PacketTest(object):
    def __init__(self):
        self.packet = None
        self.bstr = None

    def test_to_bytes(self):
        packet = Packet()
        self.packet = packet
        res = packet.to_bytes()
        self.bstr = res
        print(res)

    def test_from_bytes(self):
        res = Packet.from_bytes(self.bstr)
        print(res.type)
        print(res.lens)
        print(res.vals)

    def test_all(self):
        self.test_to_bytes()
        self.test_from_bytes()


def main():
    PacketTest().test_all()


if __name__ == "__main__":
    main()
