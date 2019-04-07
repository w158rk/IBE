####################################################### log setting
## is there any way to set this gloabally?

import logging

logging.basicConfig(level=logging.DEBUG,
                    filename='output.log',
                    datefmt='%Y/%m/%d %H:%M:%S',
                    format='%(asctime)s - %(name)s - %(levelname)s - %(lineno)d - %(module)s - %(message)s')
logger = logging.getLogger(__name__)

#####################################################

from network.packet import *

class Packer:
    ###################################
    ## make pack
    ###################################

    @classmethod
    def enpack(cls, type, *args):
        """
        take the args, output a packet corresponding to the given type
        ibe --- u, v
        extr_ack --- cipher, iv 
        extr_ask --- uid, sessionKey
        """
        # logger.debug(args)
        logger.debug(args)
        try:
            f = getattr(cls, 'enpack_'+type)
        except NameError:
            print("Not able to make the type " + type + " packet")
        else:
            return f(*args)

    @classmethod
    def enpack_IBE_ENC(cls, *args):
        packet = Packet()
        setattr(packet, 'type', "IBE_ENC")
        setattr(packet, 'u', args[0])
        setattr(packet, 'v', args[1])
        return packet

    @classmethod 
    def enpack_EXTR_ACK(cls, cipher, iv):
        # logger.debug("ACK args", args)
        packet = Packet() 
        setattr(packet, 'type', "EXTR_ACK")
        setattr(packet, 'cipher', cipher)          # encrypted message
        setattr(packet, "iv", iv)              # decrypt initial vector
        return packet

    @classmethod 
    def enpack_EXTR_ASK(cls, uid, sessionKey):
        packet = Packet() 
        setattr(packet, 'type', "EXTR_ASK")
        setattr(packet, "uid", uid)
        setattr(packet, "sessionKey", sessionKey)
        print("[enpack]" ,packet)
        return packet
    #############################################
    ## get pack info
    #############################################

    @classmethod
    def depack(cls, packet):
        """
        the content returned:
            IBE_ENC --- u and v 
            AES_ACK --- cls and cipher
        """

        fname = 'depack_'+getattr(packet, 'type')
        logger.debug(fname)
        f = getattr(cls, fname)
        return f(packet) 

    @classmethod
    def depack_IBE_ENC(cls, packet):
        return (getattr(packet, 'u'), getattr(packet, 'v'))

    @classmethod
    def depack_EXTR_ACK(cls, packet):
        return (getattr(packet, 'cipher'), getattr(packet, 'iv'))

    @classmethod
    def depack_EXTR_ASK(cls, packet):
        return (getattr(packet, 'uid'), getattr(packet, 'sessionKey'))
