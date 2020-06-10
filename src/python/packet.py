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

    def __init__(self, pack_type=PacketType.INIT_R1, lens=[], vals=[]):
        self.type = pack_type 
        self.lens = lens 
        self.vals = vals 
    
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
    def make_init_one(cls, poly, co_cnt, user_id):
        # send the f(h(ID))
        packet = Packet()
        packet.type = cls.PacketType.INIT_R1

        if type(user_id) == str:
            user_id = bytes(user_id, encoding='utf8')
        bn = SS_id2num(user_id)
        bn = SS_poly_apply(poly, co_cnt, bn)
        lens = [len(bn)]
        vals = [bn]

        packet.lens = lens
        packet.vals = vals

        return packet


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