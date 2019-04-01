import struct
import socket
from enum import Enum 

# PacketTypes
#       IBE_ENC
#       IBE_DEC
    

class Packet :
    PACK_IBE_ENC = '<8p256p256p'

    def __init__(self):
        self.type = None 
        self.u  = None 
        self.v = None 

    def toBytes(self):
        """
        converts all of the contents into a byte stream
        """
        f = getattr(self, 'toBytes_'+self.type)
        return f()
        # return struct.pack('>I', self.content)          # big-endian

    def toBytes_IBE_ENC(self):
        stream = struct.pack(Packet.PACK_IBE_ENC,bytes(self.type, encoding='utf8'), self.u, self.v)
        return stream

    def toBytes_IBE_DEC(self):
        pass

    @classmethod
    def fromBytes_IBE_ENC(cls, stream):
        packet = Packet()
        packetType, u, v = struct.unpack(Packet.PACK_IBE_ENC, stream)
        setattr(packet, 'type', 'IBE_ENC')
        setattr(packet, 'u', u)
        setattr(packet, 'v', v)
        return packet

    @classmethod
    def fromBytes(cls, stream):
        attrTuple = struct.unpack(Packet.PACK_IBE_ENC, stream)
        packetType = attrTuple[0]
        packetType = str(packetType, encoding='utf-8')
        f = getattr(cls, 'fromBytes_'+packetType)
        return f(stream)


def sendPacket(host, port, packet):
    """
    send the stream to the given ip:port
    """
    s = socket.socket()         # 创建 socket 对象

    s.connect((host, port))
    s.send(packet.toBytes())
    s.close()

def receivePacket():
    pass 

class Packer:
    @classmethod
    def enpack(cls, type, *args):
        f = getattr(cls, 'enpack_'+type)
        return f(args)

    @classmethod
    def enpack_IBE_ENC(cls, args):
        packet = Packet()
        setattr(packet, 'type', "IBE_ENC")
        setattr(packet, 'u', args[0])
        setattr(packet, 'v', args[1])
        return packet

    @classmethod
    def depack(cls, packet):
        return 'depack_'+getattr(packet, type)(packet) 

    @classmethod
    def depack_IBE_ENC(cls, packet):
        return (getattr(packet, 'u'), getattr(packet, 'v'))