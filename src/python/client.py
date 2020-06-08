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
from init import SS_new_rand_poly
from action import Action
from user import User
from packet import Packet

import sys
import socket
import argparse
import threading
import time

class Client(User):

    def gen_action_from_data(self, data):
        # TODO(wrk)
        return Action()


    def run_run(self, action):
        if action.payload == b"run_init":
            self.run_init()

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


    def run_init(self):
        """
        setup the HIBE system with secret sharing
        """

        init_user_list = self.init_user_list
        if not init_user_list:
            raise ClientError("The init cannot be invoked without the top users")

        # round one

        # sz + 1 == the number of top users
        sz = len(init_user_list)  
        co_cnt = sz + 1          
        # generate a polynomial at first
        poly = SS_new_rand_poly(co_cnt)

        self.recv_list = []
        self.sent_ack_cnt = 0

        # send the values while receiving 
        while len(self.recv_list) < sz or self.sent_ack_cnt < sz:
            for user in init_user_list:
                addr = user.addr 
                port = user.port 

                packet = Packet.make_init_one(poly, co_cnt, user.id)
                data = packet.to_bytes()

                action = Action()
                action.type = Action.ActionType.SEND
                action.payload = data
                t = threading.Thread(target=self.run_send, args=(addr, port, action))
                t.start()

            time.sleep(10)


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
            ret.payload = "run_init"

        # TODO(wxy): complete the logic of sk request 
        # and secure channel construction
        if args.action == "sk":
            ret.type = Action.ActionType.SEND
            ret.payload = "sk"

        if args.action == "comm":
            pass

        return ret


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
        client = Client(self.user_id, self.addr, self.port)
        args = self.args 
        args.action = "sk"
        client.run(self.srv_addr, self.srv_port, args=args)

    def test_client_init(self):
        server = User("Server", self.srv_addr, self.srv_port)
        client = Client(self.user_id, self.addr, self.port, init_user_list=[server])
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
