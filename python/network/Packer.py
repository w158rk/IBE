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
    def enpack_EXTR_ACK(cls, *args):
        packet = Packet() 
        setattr(packet, 'type', "EXTR_ACK")
        setattr(packet, 'cipher', args[0])          # encrypted message
        setattr(packet, "iv", args[1])              # decrypt initial vector
        return packet

    @classmethod 
    def enpack_EXTR_ASK(cls, *args):
        packet = Packet() 
        setattr(packet, 'type', "EXTR_ASK")
        setattr(packet, "uid", args[0])
        setattr(packet, "sessionKey", args[1])
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
        f = getattr(cls, fname)
        return f(packet) 

    @classmethod
    def depack_IBE_ENC(cls, packet):
        return (getattr(packet, 'u'), getattr(packet, 'v'))

    @classmethod
    def depack_EXTR_ACK(cls, packet):
        return getattr(packet, 'cipher')

    @classmethod
    def depack_EXTR_ASK(cls, packet):
        return (getattr(packet, 'uid'), getattr(packet, 'sessionKey'))
