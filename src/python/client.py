#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

'''
@File    :   client.py
@Time    :   2020/05/17 16:38:10
@Author  :   Ruikai Wang
@Version :   1.0
@Contact :   wrk15835@gmail.com
@License :   Copyright (c) 2020 Ruikai Wang
@Desc    :   functions and classes for clients

Classes:
    Client: present a client
    ClientTest: test for client

Functions:
    main: run a test client

'''

from constant import *
from action import Action
from packet import Packet

import sys
import socket
import argparse
import threading
import time

class Client(object):
    """
    Attributes:
        user:   The user on which this client is attached
    """

    def __init__(self, user):
        self.user = user
        user.client = self

    def gen_action_from_data(self, data):
        # TODO(wrk)
        action = Action()
        packet = Packet.from_bytes(data)
        if packet.type == Packet.PacketType.INIT_R1_ACK:
            print("receive ACK")
            self.user.sent_ack_cnt += 1
        return action

    def gen_action_from_args(self, args):
        """generate Action object from the args the user give when using
            this file

        Args:
            args: arguments given by shell instruction

        Returns:
            the Action object
        """
        ret = Action()
        
        # TODO(wrk): complete the logic of init
        if args.action == "init":
            ret.type = Action.ActionType.RUN
            ret.payload = [b"run_init"]

        # TODO(wxy): complete the logic of sk request 
        # and secure channel construction
        if args.action == "sk":
            ret.type = Action.ActionType.SEND
            ret.payload = [b"sk"]

        if args.action == "comm":
            pass

        return ret

    def run_run(self, action):
        if action.payload[0] == b"run_init":
            self.user.run_init()

    def run_send(self, addr, port, action):
        """
        send data to addr:port 

        Ensure:
            the list action.payload only contain the data to be sent
        """

        if not addr or not port:
            raise ClientError("Unknown target for SEND")

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        srv_addr = (addr, port)
        sock.connect(srv_addr)

        try:
            while True:
                if not action:
                    break
                if action.type == Action.ActionType.ABORT:
                    # TODO(wrk): log some error information
                    break
                if action.type == Action.ActionType.EXIT:
                    break
                if action.type == Action.ActionType.SEND:
                    assert (len(action.payload) == 1)
                    print("send: ", action.payload[0])
                    sock.sendall(action.payload[0])
                if action.type == Action.ActionType.RUN:
                    # TODO(wrk): Is this line possible?
                    self.run_run(action)

                data = sock.recv(BUFFER_SIZE)
                print("received: ", data)
                action = self.gen_action_from_data(data)

        except socket.error as e:
            print("Socket Error: %s" % str(e))
        except AssertionError as e:
            print("Assertion Error: %s" % str(e))
        except Exception as e:
            print("Other exception: %s" % str(e))
        finally:
            sock.close()


    def run(self, srv_host=None, srv_port=None, action=None, args=None):
        """
        do the actual behavior as the action or args identified

        neither srv_host nor sev_port should be None if action.type = SEND 
        """


        if args:
            action = self.gen_action_from_args(args)

        if action.type == Action.ActionType.SEND:
            self.run_send(srv_host, srv_port, action)
        if action.type == Action.ActionType.RUN:
            self.run_run(action)





class ClientTest(object):
    """class for client tests

    Attributes:
        client: the Client object
        srv_addr: the address of server host
        srv_port: the port of server
        args: the arguments given by the user

    Tests:
        Client.run
    """

    def __init__(self, user_id="Client", addr="0.0.0.0", port=10011,
                 srv_addr="localhost", srv_port=10010, args=None):
        self.user_id = user_id
        self.addr = addr 
        self.port = port
        self.srv_addr = srv_addr
        self.srv_port = srv_port
        self.args = args

    def test_client_run(self):
        from user import User
        user = User(self.user_id, self.addr, self.port)
        client = Client(user)
        args = self.args 
        args.action = "sk"
        client.run(self.srv_addr, self.srv_port, args=args)

    def test_client_init(self):
        from user import User
        server = User("Server", self.srv_addr, self.srv_port)
        user = User(self.user_id, self.addr, self.port, init_user_list=[server])
        client = Client(user)
        args = self.args 
        args.action = "init"
        client.run(args=args)

    def test_all(self):
        self.test_client_run()
        self.test_client_init()



class ClientError(Exception):
    def __init__(self, err='Error in Client Module'):
        Exception.__init__(self, err)


def main():
    valid_actions = {
        "init": "invoke an initialization",
        "sk": "request for the private key",
        "comm": "initialize a secret session"
    }

    parser = argparse.ArgumentParser(description="IBE Client")
    parser.add_argument("--server-ip", action="store", dest="srv_addr",
                        type=str, default="localhost")
    parser.add_argument("--server-port", action="store", dest="srv_port",
                        type=int, default=10010)
    parser.add_argument("--action", action="store", dest="action", default="sk",
                        choices=valid_actions.keys(),
                        help="the valid actions are: %s" % str(valid_actions))

    args = parser.parse_args()
    client_test = ClientTest(srv_addr=args.srv_addr, srv_port=args.srv_port,
                             args=args)
    client_test.test_all()


if __name__ == "__main__":
    main()
