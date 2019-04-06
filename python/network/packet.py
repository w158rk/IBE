# PacketTypes
#       IBE_ENC
#       IBE_DEC
#       Extr_ASK
#       Extr_ACK    

from struct import pack, unpack
from enum import Enum 

"""
the only public interfaces are:
    Packet.fromStream()
    PacketInvalidError()
"""

class Packet :
    PACK_IBE_ENC = '<8p256p256p'
    PACK_Extr_ASK = '<16p256p256p'
    PACK_Extr_ACK = '<16p256p'

    def __init__(self):
        self.type = None 
        self.u  = None 
        self.v = None 
        self.cipher = None

    #######################
    ## to bytes functinos
    #######################
    def toBytes(self):
        """
        converts all of the contents into a byte stream
        
        no args

        return: the byte stream corresponding to the object
        """
        f = getattr(self, 'toBytes_'+self.type)
        return f()

    def toBytes_IBE_ENC(self):
        stream = pack(Packet.PACK_IBE_ENC,
            bytes(self.type, encoding='utf8'), self.u, self.v)
        return stream

    def toBytes_IBE_DEC(self):
        pass

    def toBytes_Extr_ASK(self): # finished
        pass
        # stream = pack(Packet.PACK_Extr_ASK, )

    def toBytes_Extr_ACK(self):
        stream = pack(Packet.PACK_Extr_ACK, bytes(self.type, encoding="utf8"), self.cipher)
        return stream


    #######################
    ## to bytes functinos
    #######################
    @classmethod
    def fromBytes_IBE_ENC(cls, stream):
        packet = Packet()
        packetType, u, v = unpack(Packet.PACK_IBE_ENC, stream)
        setattr(packet, 'type', "IBE_ENC")
        setattr(packet, 'u', u)
        setattr(packet, 'v', v)
        return packet

    @classmethod
    def fromBytes(cls, stream):
        """
        [class method] get a packet from byte stream
        args:
            stream : list of bytes 
        return:
            an object of class Packet
        """
        attrTuple = unpack(Packet.PACK_IBE_ENC, stream)
        packetType = attrTuple[0]
        packetType = str(packetType, encoding='utf-8')
        f = getattr(cls, 'fromBytes_'+packetType)
        return f(stream)

    @classmethod
    def fromBytes_Extr_ACK(cls, stream):                # get the encrypted ACK message
                                                        # with the private key of that user
        packet = Packet()
        _, cipher = unpack(Packet.PACK_IBE_ENC, stream)
        setattr(packet, 'type', "Extr_ACK")
        setattr(packet, 'cipher', cipher)

class PacketInvalidError(TypeError):
    def __init__(self, info):
        self.info = info