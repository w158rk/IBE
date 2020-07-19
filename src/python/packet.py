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
from utils import str2bytes

import os


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
        SK_RESPOND_KEY = 11
        SK_KEY_ACK = 12
        SK_KEY_ACK_ACK = 13

    def __init__(self, pack_type=PacketType.INIT_R1, lens=[], vals=[]):
        self.type = pack_type
        self.lens = lens
        self.vals = vals

    @classmethod
    def from_bytes(cls, bstr):
        index = 0
        ret = Packet()

        pack_type = int.from_bytes(bstr[index: index+2], "little")
        pack_type = cls.PacketType(pack_type)
        ret.type = pack_type

        index += 2
        sz = int.from_bytes(bstr[index: index+2], "little")

        # read the lens
        index += 2
        lens = []
        for i in range(sz):
            lens.append(int.from_bytes(bstr[index: index+2], "little"))
            index += 2
        ret.lens = lens

        # read the values
        vals = []
        for l in lens:
            vals.append(bstr[index: index+l])
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
    def make_sk_respond_init(cls, mpk_file="./mpk_file"):
        """
        read the content of the given files, TODO(wxy): certificate left
        """

        assert os.path.exists(mpk_file)

        mpk = b""
        with open(mpk_file, "rb") as f:
            mpk = f.read()

        packet = Packet()
        packet.type = cls.PacketType.SK_RESPOND_INIT

        lens = [len(mpk)]
        vals = [mpk]

        packet.lens = lens
        packet.vals = vals

        return packet

    @classmethod
    def make_sk_request_key_plain(cls, key=b""):
        """
        make a packet with a random key
        """

        assert key
        packet = Packet()
        packet.type = cls.PacketType.SK_REQUEST_KEY_PLAIN

        lens = [len(key)]
        vals = [key]

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

        lens = [l.to_bytes(2, 'little') for l in self.lens]
        lens = b''.join(lens)

        vals = b''.join(self.vals)
        return b''.join([header, lens, vals])


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
