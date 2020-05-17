#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

'''
@File    :   server.py
@Time    :   2020/05/17 15:55:01
@Author  :   Ruikai Wang 
@Version :   1.0
@Contact :   wrk15835@gmail.com
@License :   Copyright (c) 2020 Ruikai Wang
@Desc    :   classes and functions for a server. 

Literally, a server listens on a port, receives packets and makes replies.
The logic about handling the packets is not defined in this file, only 
basic send/recv functions are defined here. A interface for the handling 
function exists.
'''

from action import Action
from user import User

import sys
import socket
import threading

BUFFER_SIZE = 1024

def handle_bytes_interface(data):
    """this is an interface for handling the protocol packets. 

    Args:
        data: the received byte stream
    """
    
    #TODO(wrk)
    action = Action()
    if data == b"sk":
        action.type = Action.ActionType.SEND_AND_EXIT
        action.payload = "sk received"

    return action

def handle_thread(server, sock, addr):
    """the main function of handle thread

    Here we get byte stream from network, makes corresponding replies, 
    sometimes maintains a "session"
    """

    try:
        while True:
            data = sock.recv(BUFFER_SIZE)
            if data:

                # TODO(wrk): maybe generate some log information
                
                print("received: ", data)
                action = handle_bytes_interface(data) 
                if action:
                    if action.type == Action.ActionType.EXIT:
                        break
                    if action.type == Action.ActionType.ABORT:
                        #TODO(wrk): log some error infomation
                        break
                    if action.type == Action.ActionType.SEND:
                        print("send: ", action.payload)
                        sock.send(action.payload)
                    if action.type == Action.ActionType.SEND_AND_EXIT:
                        print("send: ", action.payload)
                        sock.send(action.payload)
                        break
        
        sock.close()

    except socket.error as e:
        print("Socket error: %s" % str(e))
    except Exception as e:
        print("Other exception: %s" % str(e))

class Server(User):
    """class representing a server

    Attributes:
        MAX_NUM_CLIENTS: the maximum number of accepted clients
        num_clients: the current number of clients

    Functions:
        run(): the main function of the server 
    """

    def __init__(self, user_id, addr, port):
        super(Server, self).__init__(user_id, addr, port) 
        self.MAX_NUM_CLIENTS = 10
        self.num_clients = 0

    def run(self):

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # bind the address and port 
        srv_addr = (self.addr, self.port)
        sock.bind(srv_addr)

        sock.listen(self.MAX_NUM_CLIENTS) 

        print("server is running")
        while True:
            conn, addr = sock.accept() 
            t = threading.Thread(target=handle_thread, args=(self, conn, addr))
            t.start()

class ServerTest(object):
    """the class for testing the functionality of Server

    Attributes:
        server

    Tests:
        Server.run
    """

    def __init__(self, user_id="Server", addr="0.0.0.0", port=10010):
        self.server = Server(user_id, addr, port)

    def test_server_run(self):
        self.server.run()
    
    def test_all(self):
        self.test_server_run()

def main():
    server_test = ServerTest()
    server_test.test_all()

if __name__ == "__main__":
    main()