import logging

logging.basicConfig(level=logging.DEBUG,
                    filename='output.log',
                    datefmt='%Y/%m/%d %H:%M:%S',
                    format='%(asctime)s - %(name)s - %(levelname)s - %(lineno)d - %(module)s - %(message)s')
logger = logging.getLogger(__name__)

from abc import abstractmethod
from socket import socket, AF_INET, SOCK_STREAM

from network.packet import Packet 
from network.Packer import Packer, PacketInvalidError
from entity.crypto import encrypt, decrypt, gen_key_aes, decrypt_aes

class User:
    def __init__(self, id):
        self.id = id 
        self.sessionKey = None

    @abstractmethod
    def sendStream(self, conn, stream):
        pass

    def handleStream(self, conn, stream):
        self.handlePacket(conn, Packet.fromBytes(stream))

    def sendPacket(self, conn, packet):
        """
        send the packet to the given ip:port
        """
        self.sendStream(conn, packet.toBytes())

    def readSk(self):
        """
        get the User's sk
        """
        filename = "ibe_sk_" + self.id 
        with open(filename, "rb") as f:
            sk = f.read()
            f.close() 
        return sk

    ##########################################
    ## handle packet functions
    ##########################################

    def handlePacket(self, conn, packet):
        logger.debug(packet.iv)
        if not packet.type:
            raise PacketInvalidError 
        try:
            f = getattr(self, 'handlePacket_'+packet.type)
        except NameError:
            logger.critical("Not able to get the type of the received packet")
        else:
            return f(conn, packet)

    def handlePacket_IBE_ENC(self, conn, packet):
        u,v = Packer.depack(packet)
        sk = self.readSk()
        message = decrypt(u,v,sk)
        self.handleMessage(message)

    def handlePacket_EXTR_ACK(self, conn, packet):
        """
        extract the content, then store it in the file ibe_sk_{id}
        """
        cipher, iv = Packer.depack(packet)
        logger.debug("decrypt cipher : %s" % iv)
        logger.debug("decrypt iv : %s" % iv)
        logger.debug("decrypt session key : %s" % self.sessionKey)
        sk = decrypt_aes(cipher, self.sessionKey, iv)
        logger.debug("decrypt sk : %s" % sk)

    ##########################################
    ## make packet functions 
    ##########################################
    def makePacket(self, type, *args):
        try:
            f = getattr(self, 'makePacket_'+type)
        except NameError:
            print("Not able to make the type " + type + " packet")
        else:
            return f(*args)

    def makePacket_IBE_ENC(self, *args):
        # encrypt the message
        message = args[0]
        targetID = args[1]
        u, v = encrypt(message, targetID)

        ## make a packet
        return Packer.enpack('IBE_ENC', u, v)

    def makePacket_EXTR_ASK(self, *args):
        """
        id and aes secret key
        """
        uid = self.id 
        r = gen_key_aes()
        self.sessionKey = r
        logger.debug(uid)
        return Packer.enpack('EXTR_ASK', uid, r)

    ###########################################
    ## handle message functions 
    ##########################################
    @abstractmethod
    def handleMessage(self, message):
        """
        message : string vector
        """



