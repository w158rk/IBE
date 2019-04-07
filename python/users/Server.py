from users.Base import User 

from socket import socket, AF_INET, SOCK_STREAM
from threading import Thread

class Server(User):

    def __init__(self, id, port=None, host='localhost'):
        super(Server, self).__init__(id)
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
            conn,_ = self.socket.accept()             
            while True:
                try:
                    data = conn.recv(1024)  #接收数据
                    if not data:
                        break
                    t = Thread(target=self.handleStream, args=(conn, data))
                    t.start()
                except ConnectionResetError:
                    print('关闭了正在占线的链接！')
                    break
            
    def sendStream(self, conn, stream):
        if not self.isRun:
            raise ServerNotRunError
        conn.send(stream)

class ServerNotRunError(RuntimeError):
    def __init__(self, info):
        self.info = info
