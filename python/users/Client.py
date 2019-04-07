import logging

logging.basicConfig(level=logging.DEBUG,
                    filename='output.log',
                    datefmt='%Y/%m/%d %H:%M:%S',
                    format='%(asctime)s - %(name)s - %(levelname)s - %(lineno)d - %(module)s - %(message)s')
logger = logging.getLogger(__name__)

from users.Base import User 

from socket import socket, error


class Client(User):
    
    def __init__(self, id):
        super(Client, self).__init__(id)
        self.socket = None

    def sendStream(self, conn, stream):
        conn.send(stream)

    def connectToServer(self, host, port):
        s = socket()
        s.connect((host, port))
        self.socket = s

    def getPrivateKey(self):
        packet = self.makePacket("EXTR_ASK")
        # need configure the kgc address
        host = "localhost"
        port = 12345
        self.connectToServer(host, port)   
        try:              
            self.sendPacket(self.socket, packet) 
        except error:
            print("socket is unusable")
        else:
            data = self.socket.recv(1024)
            if not data:
                print("no data receive ...")
            else:
                self.handleStream(self.socket, data)
        finally:
            self.socket.close()