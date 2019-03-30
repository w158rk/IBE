from network.network import *
from entity.crypto import *

class User():
    def __init__(self, id):
        self.id = id 
    
class Server(User):

    def __init__(self, id, port=None, host='localhost'):
        self.id = id 
        self.host = host 
        self.port = port


    def run(self):
        server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        port = getattr(self, 'port')
        server.bind(('localhost',port)) #绑定要监听的端口
        server.listen(5) #开始监听 表示可以使用五个链接排队
        print("runnning ...")
        while True:# conn就是客户端链接过来而在服务端为期生成的一个链接实例
            conn,addr = server.accept() #等待链接,多个链接的时候就会出现问题,其实返回了两个值
            print(conn,addr)
            while True:
                try:
                    data = conn.recv(1024)  #接收数据
                    if(len(data)==0):
                        break
                    self.parse(data)
                    print("finished")
                    conn.send(data.upper()) #然后再发送数据
                except ConnectionResetError as e:
                    print('关闭了正在占线的链接！')
                    break
            conn.close()

    def parse(self, stream):
        packet = Packet.fromBytes(stream)
        f = getattr(self, 'parsePack_'+packet.type)
        return f(packet)

    def parsePack_IBE_ENC(self, packet):
        u = packet.u 
        v = packet.v 
        with open("U_"+self.id, "wb") as f:
            f.write(u)
            f.close()
        with open("V_"+self.id, "wb") as f:
            f.write(v)
            f.close()
        decrypt(self.id)

    def send(self, m, dest, host, port):
        """ encrypt and send m to the given host and port"""
        encrypt(m, self.id)
        u = None
        v = None
        with open("U_"+dest, 'rb') as f:
            u = f.read()
            f.close() 
        with open("V_"+dest, 'rb') as f:
            v = f.read() 
            f.close() 
        
        #########################
        ## make a packet
        #########################

        packet = Packer.enpack('IBE_ENC', u, v)

        #########################
        ## send the packet
        #########################

        sendPacket(host, port, packet)    

class Client(User):
    
    def __init__(self, id):
        self.id = id 

    def send(self, m, dest, host, port):
        """ encrypt and send m to the given host and port"""
        encrypt(m, dest)
        u = None
        v = None
        with open("U_"+dest, 'rb') as f:
            u = f.read()
            f.close() 
        with open("V_"+dest, 'rb') as f:
            v = f.read() 
            f.close() 
        
        #########################
        ## make a packet
        #########################

        packet = Packer.enpack('IBE_ENC', u, v)

        #########################
        ## send the packet
        #########################

        sendPacket(host, port, packet)
        

