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
    Client: present clients
    ClientTest: test for client

Functions:
    main: run a test client

'''

from constant import *
from action import Action
from user import User

import sys
import socket
import argparse


class Client(User):

    def gen_action_from_data(self, data):
        # TODO(wrk)
        return Action()

    def run(self, srv_host, srv_port, action=None):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        srv_addr = (srv_host, srv_port)
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
                    print("send: ", action.payload)
                    sock.sendall(action.payload)

                data = sock.recv(BUFFER_SIZE)
                print("received: ", data)
                action = self.gen_action_from_data(data)

        except socket.error as e:
            print("Socket Error: %s" % str(e))
        except Exception as e:
            print("Other exception: %s" % str(e))
        finally:
            sock.close()


class ClientTest:
    """class for client tests

    Attributes:
        client: the Client object
        srv_addr: the address of server host
        srv_port: the port of server
        action: the action used for test

    Tests:
        Client.run
    """

    def __init__(self, user_id="Client", addr="0.0.0.0", port=10011,
                 srv_addr="localhost", srv_port=10010, action=None):
        self.client = Client(user_id, addr, port)
        self.srv_addr = srv_addr
        self.srv_port = srv_port
        if not action:
            action = Action()
        self.action = action

    def test_client_run(self):
        print(self.action.type, ", ", self.action.payload)
        self.client.run(self.srv_addr, self.srv_port, self.action)

    def test_all(self):
        self.test_client_run()


def gen_action_from_args(args):
    """generate Action object from the args the user give when using
        this file

    Args:
        args: arguments given by shell instruction

    Returns:
        the Action object
    """
    ret = Action()

    if args.action == "init":
        pass

    if args.action == "sk":
        ret.type = Action.ActionType.SEND
        ret.payload = "sk"

    if args.action == "comm":
        pass

    return ret


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
    action = gen_action_from_args(args)
    client_test = ClientTest(srv_addr=args.srv_addr, srv_port=args.srv_port,
                             action=action)
    client_test.test_all()


if __name__ == "__main__":
    main()
