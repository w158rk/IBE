from network.packet import *

class Packer:
    ###################################
    ## make pack
    ###################################

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

    #############################################
    ## get pack info
    #############################################

    @classmethod
    def depack(cls, packet):
        return 'depack_'+getattr(packet, type)(packet) 

    @classmethod
    def depack_IBE_ENC(cls, packet):
        return (getattr(packet, 'u'), getattr(packet, 'v'))
