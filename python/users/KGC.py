from entity.crypto import extract
from network.packet import Packer
from users.Base import Server 

class KGC(Server):
    def __init__(self, id, port=None, host='localhost'):
        super(KGC, self).__init__(self, id, port, host)
    
    def handlePacket_Extr_Ask(self, host, port, packet):
        id = packet.id 
        sessionKey = packet.sessionKey                 # used to protect the sk
        extract(id)
        msg = sessionKey 
        with open("pk_"+id, "rb") as f:
            pk = f.read()
            msg = msg + "key:" + pk + "\n"
            f.close() 
        with open("sk_"+id, "rb") as f:
            sk = f.read()
            msg = msg + "key:" + sk + "\n"
            f.close()

        self.makePacket_Extr_ACK(msg, id)

    def makePacket_Extr_ACK(self, message, targetID):
        return Packer.enpack('Extr_ACK', message, targetID)

