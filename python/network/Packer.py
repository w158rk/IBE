from network.packet import *

class Packer:
    ###################################
    ## make pack
    ###################################

    @classmethod
    def enpack(cls, type, *args):
        """
        take the args, output a packet corresponding to the given type
        """
        f = getattr(cls, 'enpack_'+type)
        return f(args)

    @classmethod
    def enpack_IBE_ENC(cls, *args):
        packet = Packet()
        setattr(packet, 'type', "IBE_ENC")
        setattr(packet, 'u', args[0])
        setattr(packet, 'v', args[1])
        return packet

    @classmethod 
    def enpack_AES_ACK(cls, *args):
        packet = Packet() 
        setattr(packet, 'type', "AES_ACK")
        setattr(packet, 'cipher', args[0])          # encrypted message
        return packet

    # @classmethod 
    # def enpack_AES_ASK(cls, *args):
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
        f = getattr(cls, fname)
        return f(packet) 

    @classmethod
    def depack_IBE_ENC(cls, packet):
        return (getattr(packet, 'u'), getattr(packet, 'v'))

    @classmethod
    def depack_AES_ACK(cls, packet):
        return getattr(packet, 'cipher')
