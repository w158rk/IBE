# 2019.10.29

1. 将socket_main改为静态方法，对每个client单独分配一个Comm对象

#### Server 结构 

        Server (User)
            |
            |
            |-----监听线程，等待连接(Comm+Packet)
            |
            |
            |-----服务线程(Comm+Packet)
            |
            |-----……
            |
            '-----服务线程(Comm+Packet)

#### Client 结构

        Server (User)
            |
            |
            |-----主线程，连接服务器，UI(Comm+Packet)
            |
            |
            '-----监听线程(Comm+Packet)


2. Comm对象负责通信和监听（主线程和监听线程共享一个对象）

3. sm4key存在User里
