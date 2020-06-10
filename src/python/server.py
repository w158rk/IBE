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
from packet import Packet

import sys
import socket
import threading

BUFFER_SIZE = 1024






class Server(object):
    """class representing a server

    Attributes:
        MAX_NUM_CLIENTS: the maximum number of accepted clients
        num_clients: the current number of clients

    Functions:
        run(): the main function of the server
    """

    def __init__(self, user):
        self.user = user
        user.server = self
        self.MAX_NUM_CLIENTS = 10
        self.num_clients = 0

    def gen_action_from_data(self, data):
        """this is an interface for handling the protocol packets.

        Args:
            data: the received byte stream
        """

        # TODO(wrk)
        action = Action()
        if data == b"sk":
            action.type = Action.ActionType.SEND_AND_EXIT
            action.payload = b"sk received"
            return action

        packet = Packet.from_bytes(data)
        if packet.type == Packet.PacketType.INIT_R1:
            # add the payload into the recv_list

            run_action = Action()
            run_action.type = Action.ActionType.RUN
            run_action.payload = [b"run_init", packet.vals[0]]

            send_action = Action()
            send_action.type = Action.ActionType.SEND 
            send_action.payload = Packet(Packet.PacketType.INIT_R1_ACK).to_bytes()

            action.type = Action.ActionType.SEND_AND_RUN
            action.payload = [send_action, run_action]

        if packet.type == Packet.PacketType.INIT_R1_ACK:
            print("receive ACK")
            self.user.sent_ack_cnt += 1

        return action

    def run(self):

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # bind the address and port
        srv_addr = (self.user.addr, self.user.port)
        sock.bind(srv_addr)

        sock.listen(self.MAX_NUM_CLIENTS)

        print("server is running")
        while True:
            conn, addr = sock.accept()
            t = threading.Thread(target=self.handle_thread, args=(conn, addr))
            t.start()

    def run_run(self, action):
        if action.payload[0] == b"run_init":
            _, val = action.payload
            self.user.run_init(with_val=val, is_listening=True)

    def handle_thread(self, sock, addr, user=None):
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
                    action = self.gen_action_from_data(data)
                    if action:
                        if action.type == Action.ActionType.EXIT:
                            break
                        if action.type == Action.ActionType.ABORT:
                            # TODO(wrk): log some error infomation
                            break
                        if action.type == Action.ActionType.SEND:
                            print("send: ", action.payload)
                            sock.send(action.payload)
                        if action.type == Action.ActionType.SEND_AND_EXIT:
                            print("send: ", action.payload)
                            sock.send(action.payload)
                            break
                        if action.type == Action.ActionType.RUN:
                            if action.payload[0] == b"run_init":
                                self.run_run(action)
                        if action.type == Action.ActionType.SEND_AND_RUN:
                            send_action, run_action = action.payload
                            sock.send(send_action.payload)
                            self.run_run(run_action)


            sock.close()

        except socket.error as e:
            print("Socket error: %s" % str(e))
        except Exception as e:
            print("Other exception: %s" % str(e))




class ServerTest(object):
    """the class for testing the functionality of Server

    Attributes:
        server

    Tests:
        Server.run
    """

    def __init__(self, user_id="Server", addr="0.0.0.0", port=10010):
        from user import User
        server2 = User("Server", "127.0.0.1", 10011)
        self.user = User(user_id, addr, port, init_user_list=[server2])
        self.server = Server(self.user)

    def test_server_run(self):
        self.server.run()

    def test_all(self):
        self.test_server_run()


def main():
    server_test = ServerTest()
    server_test.test_all()


if __name__ == "__main__":
    main()
