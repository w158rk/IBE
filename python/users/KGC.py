import logging

logging.basicConfig(level=logging.DEBUG,
                    datefmt='%Y/%m/%d %H:%M:%S',
                    format='%(asctime)s - %(name)s - %(levelname)s - %(lineno)d - %(module)s - %(message)s')
logger = logging.getLogger(__name__)

from entity.crypto import extract, encrypt_aes, gen_iv_aes, setup
from network.Packer import Packer
from users.Server import Server 

class KGC(Server):
    def __init__(self, id, port=None, host='localhost'):
        print(type(super(KGC, self)))
        super(KGC, self).__init__(id, port=port, host=host)
    
    def handlePacket_EXTR_ASK(self, conn, packet):
        uid, sessionKey = Packer.depack(packet)
        sk = extract(uid)
        logger.debug("extracted key : %s" % sk)
        logger.debug("extracted key length : %d" % len(sk))
        iv = gen_iv_aes()
        cipher = encrypt_aes(sk, sessionKey, iv)
        logging.debug(cipher)
        logging.debug(iv)
        response = self.makePacket("EXTR_ACK", cipher, iv)
        try: 
            self.sendPacket(conn, response)
        except RuntimeError:
            logger.debug("RuntimeError")
            conn.close()
        else:
            pass
            

    def makePacket_EXTR_ACK(self, cipher, iv):
        return Packer.enpack('EXTR_ACK', cipher, iv)

    def system_setup(self):
        setup()

    def run(self):
        self.system_setup()
        super(KGC, self).run() 