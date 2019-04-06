from abc import abstractmethod
from socket import socket, AF_INET, SOCK_STREAM

from network.packet import Packet 
from network.Packer import Packer, PacketInvalidError
from entity.crypto import encrypt, decrypt

class User:
    def __init__(self, id):
        self.id = id 

    @abstractmethod
    def sendStream(self, host, port, stream):
        pass

    def handleStream(self, host, port, stream):
        self.handlePacket(host, port, Packet.fromBytes(stream))

    def sendPacket(self, host, port, packet):
        """
        send the packet to the given ip:port
        """
        self.sendStream(host, port, packet.toBytes())

    ##########################################
    ## handle packet functions
    ##########################################

    def handlePacket_IBE_ENC(self, host, port, packet):
        u,v = Packer.depack(packet)
        with open("U_"+self.id, "wb") as f:
            f.write(u)
            f.close()
        with open("V_"+self.id, "wb") as f:
            f.write(v)
            f.close()
        message = decrypt(self.id)
        self.handleMessage(message)

    def handlePacket(self, host, port, packet):
        if not packet.type:
            raise PacketInvalidError 
        try:
            f = getattr(self, 'handlePacket_'+packet.type)
        except NameError:
            print("Not able to get the type of the received packet")
        else:
            return f(host, port, packet)

    ##########################################
    ## make packet functions 
    ##########################################
    def makePacket(self, type, message, targetID):
        try:
            f = getattr(self, 'makePacket_'+type)
        except NameError:
            print("Not able to make the type " + type + " packet")
        else:
            return f(message, targetID)

    def makePacket_IBE_ENC(self, message, targetID):
        # encrypt the message
        encrypt(message, targetID)
        u = None
        v = None
        with open("U_"+targetID, 'rb') as f:
            u = f.read()
            f.close() 
        with open("V_"+targetID, 'rb') as f:
            v = f.read() 
            f.close() 
        
        ## make a packet
        return Packer.enpack('IBE_ENC', u, v)

    ###########################################
    ## handle message functions 
    ##########################################
    @abstractmethod
    def handleMessage(self, message):
        """
        message : string vector
        """

class Server(User):

    def __init__(self, id, port=None, host='localhost'):
        self.id = id 
        self.host = host 
        self.port = port
        self.socket = None
        self.isRun = False

    def run(self):
        """
        just continuouslly receive packets and transport them to the packet
        handle process
        """
        self.socket = socket(AF_INET,SOCK_STREAM)
        port = getattr(self, 'port')
        self.socket.bind((self.host,port))                           #绑定要监听的端口
        self.socket.listen(5)                            #开始监听 表示可以使用五个链接排队
        self.isRun = True
        print("runnning ...")
        while True:
            # conn就是客户端链接过来而在服务端为期生成的一个链接实例
            conn,addr = self.socket.accept()             
            print(conn,addr)
            while True:
                try:
                    data = conn.recv(1024)  #接收数据
                    if not data:
                        break
                    self.handleStream(addr[0], addr[1], data)
                except ConnectionResetError:
                    print('关闭了正在占线的链接！')
                    break
            conn.close()
            
    def sendStream(self, host, port, stream):
        if not self.isRun:
            raise ServerNotRunError
        s = self.socket                  # 创建 socket 对象
        s.connect((host, port))
        s.send(stream)
        s.close()


class Client(User):
    
    def __init__(self, id):
        super(Client, self).__init__(id)

    def handlePacket(self, host, port, packet):
        pass

    def sendStream(self, host, port, stream):
        s = socket()         # 创建 socket 对象
        s.connect((host, port))
        s.send(stream)
        s.close()

class ServerNotRunError(RuntimeError):
    def __init__(self, info):
        self.info = info