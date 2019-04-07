# PacketTypes
#       IBE_ENC
#       IBE_DEC
#       EXTR_ASK
#       EXTR_ACK    

import logging

logging.basicConfig(level=logging.DEBUG,
                    filename='output.log',
                    datefmt='%Y/%m/%d %H:%M:%S',
                    format='%(asctime)s - %(name)s - %(levelname)s - %(lineno)d - %(module)s - %(message)s')
logger = logging.getLogger(__name__)

from struct import pack, unpack, error
from enum import Enum 

"""
the only public interfaces are:
    Packet.fromStream()
    PacketInvalidError()
"""

class Packet :
    PACK_FORMAT = '<16p256p256p'

    def __init__(self):
        self.type = None 
        self.u  = None 
        self.v = None 
        self.cipher = None
        self.iv = None
        self.uid = None
        self.sessionKey = None
        

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
        stream = pack(Packet.PACK_FORMAT,
            bytes(self.type, encoding='utf8'), self.u, self.v)
        return stream

    def toBytes_IBE_DEC(self):
        pass

    def toBytes_EXTR_ASK(self): # finished
        logger.debug(self.uid)
        uid = bytes(self.uid, encoding='utf8')
        stream = pack(Packet.PACK_FORMAT, 
            bytes(self.type, encoding='utf8'), uid, self.sessionKey)
        return stream

    def toBytes_EXTR_ACK(self):
        stream = pack(Packet.PACK_FORMAT, 
            bytes(self.type, encoding="utf8"), self.cipher, self.iv)
        return stream


    #######################
    ## to bytes functinos
    #######################
    @classmethod
    def fromBytes(cls, stream):
        """
        [class method] get a packet from byte stream
        args:
            stream : list of bytes 
        return:
            an object of class Packet
        """
        attrTuple = unpack(Packet.PACK_FORMAT, stream)
        packetType = attrTuple[0]
        packetType = str(packetType, encoding='utf-8')
        f = getattr(cls, 'fromBytes_'+packetType)
        return f(stream)

    @classmethod
    def fromBytes_IBE_ENC(cls, stream):
        packet = Packet()
        _, u, v = unpack(Packet.PACK_FORMAT, stream)
        setattr(packet, 'type', "IBE_ENC")
        setattr(packet, 'u', u)
        setattr(packet, 'v', v)
        return packet

    @classmethod
    def fromBytes_EXTR_ACK(cls, stream):                # get the encrypted ACK message
                                                        # with the private key of that user
        packet = Packet()
        _, cipher, iv = unpack(Packet.PACK_FORMAT, stream)
        setattr(packet, 'type', "EXTR_ACK")
        setattr(packet, 'cipher', cipher)
        logger.debug(cipher)
        setattr(packet, 'iv', iv)
        logger.debug(iv)
        return packet

    @classmethod
    def fromBytes_EXTR_ASK(cls, stream):                # get the encrypted ACK message
                                                        # with the private key of that user
        packet = Packet()
        _, uid, sessionKey = unpack(Packet.PACK_FORMAT, stream)
        uid = str(uid, encoding="utf-8")
        setattr(packet, 'type', "EXTR_ASK")
        setattr(packet, 'uid', uid)
        setattr(packet, 'sessionKey', sessionKey)
        return packet

class PacketInvalidError(TypeError):
    def __init__(self, info):
        self.info = info