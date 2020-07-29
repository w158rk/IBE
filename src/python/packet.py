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
        SK_REQUEST_INIT = 7
        SK_RESPOND_INIT = 8
        SK_REQUEST_KEY_PLAIN = 9
        SK_REQUEST_KEY_SEC = 10
        SK_RESPOND_KEY_PLAIN = 11
        SK_RESPOND_KEY_SEC = 12
        SK_KEY_ACK = 13
        SK_KEY_ACK_ACK = 14
        COMM_REQUEST_INIT = 15
        COMM_RESPOND_INIT = 16
        KEY_REQUEST_PLAIN = 17
        KEY_REQUEST_SEC = 18
        KEY_RESPOND = 19

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
        print("vals: ", vals)
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
    def make_init_3(cls, point, mpk_file="./mpk"):
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

    @classmethod
    def make_sk_request_init(cls, user_id):
        """
        plaintext, with only the user_id
        """

        packet = Packet()
        packet.type = cls.PacketType.SK_REQUEST_INIT

        lens = [len(user_id)]
        vals = [user_id]

        packet.lens = lens
        packet.vals = vals

        return packet

    @classmethod
    def make_sk_respond_init(cls, mpkglobal_file="./mpk-global.conf", mpk_file="./mpk_file"):
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
        packet.type = cls.PacketType.SK_RESPOND_INIT

        lens = [len(global_mpk), len(mpk)]
        vals = [global_mpk, mpk]

        packet.lens = lens
        packet.vals = vals

        return packet

    @classmethod
    def make_sk_request_key_plain(cls, key=b'', user_id=b''):
        """
        make a packet with a random key
        """

        assert key
        assert user_id
        packet = Packet()
        packet.type = cls.PacketType.SK_REQUEST_KEY_PLAIN
        print(key)

        lens = [len(key), len(user_id)]
        vals = [key, user_id]

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
    def make_sk_respond_key_plain(cls, user_sk=b'', sk_len=b'', client_sig=b'', sig_len=b''):
        """
        make the packet with client's sk and sk length
        """
        assert user_sk
        assert sk_len
        assert client_sig
        assert sig_len

        packet = Packet()
        packet.type = cls.PacketType.SK_RESPOND_KEY_PLAIN

        lens = [len(user_sk), len(sk_len), len(client_sig), len(sig_len)]
        vals = [user_sk, sk_len, client_sig, sig_len]

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

    @classmethod
    def make_comm_request_init(cls, des_id=b'', src_id=b'', father_id=b'', mpk=b'', sig=b""):
        """
        for the first communication init
        """
        assert des_id
        assert src_id
        assert father_id
        assert mpk
        assert sig

        packet = Packet()
        packet.type = cls.PacketType.COMM_REQUEST_INIT

        lens = [len(des_id), len(src_id), len(father_id), len(mpk), len(sig)]
        vals = [des_id, src_id, father_id, mpk, sig]

        packet.lens = lens
        packet.vals = vals

        return packet

    @classmethod
    def make_comm_respond_init(cls, mode=b'', des_id=b'', src_id=b'', mpk=b'', sig=b''):
        """
        for the first communication init respond

        mode:
            1: same domin
            2: cross domin
            3: comm with father node
        """
        assert des_id
        assert src_id
        assert mpk
        assert sig

        packet = Packet()
        packet.type = cls.PacketType.COMM_RESPOND_INIT

        lens = [len(mode), len(des_id), len(src_id), len(mpk), len(sig)]
        vals = [mode, des_id, src_id, mpk, sig]

        packet.lens = lens
        packet.vals = vals

        return packet

    @classmethod
    def make_key_request_plain(cls, des_id=b'', src_id=b'', key=b''):
        assert des_id
        assert src_id
        assert key

        packet = Packet()
        packet.type = cls.PacketType.KEY_REQUEST_PLAIN

        lens = [len(des_id), len(src_id), len(key)]
        vals = [des_id, src_id, key]

        packet.lens = lens
        packet.vals = vals

        return packet

    @classmethod
    def make_key_request_sec(cls, mode=b'', cipher=b'', sign=b''):
        """
        just make the cipher in the packet
        """
        assert mode
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
    def make_key_respond(cls, des_id=b'', src_id=b'', m=b''):
        assert des_id
        assert src_id
        assert m

        packet = Packet()
        packet.type = cls.PacketType.KEY_RESPOND

        lens = [len(des_id), len(src_id), len(m)]
        vals = [des_id, src_id, m]

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
