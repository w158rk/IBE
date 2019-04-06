from entity.crypto import extract, encrypt_aes, gen_iv_aes
from network.Packer import Packer
from users.Base import Server 

class KGC(Server):
    def __init__(self, id, port=None, host='localhost'):
        p = port 
        h = host
        print(type(super(KGC, self)))
        super(KGC, self).__init__(id, port=p, host=h)
    
    def handlePacket_EXTR_ASK(self, host, port, packet):
        uid, sessionKey = Packer.depack(packet)
        sk = extract(uid)
        iv = gen_iv_aes
        cipher = encrypt_aes(sk, sessionKey, iv) 
        response = self.makePacket(cipher, iv)
        self.sendPacket(host, port, response)

    def makePacket_Extr_ACK(self, *args):
        return Packer.enpack('Extr_ACK', args)

