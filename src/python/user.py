#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

'''
@File    :   user.py
@Time    :   2020/05/17 16:23:16
@Author  :   Ruikai Wang
@Version :   1.0
@Contact :   wrk15835@gmail.com
@License :   Copyright (c) 2020 Ruikai Wang
@Desc    :   Class for presenting a user in the network
'''

from action import Action
from constant import *
from init import SS_new_rand_poly
from packet import Packet
from client import Client 
from server import Server

import socket 
import threading
import time


class User(object):
    """class presenting users in the network

    Attributes:
        id: the identification
        addr: the IP address
        port: the port on which the user is running
    """

    def __init__(self, user_id, addr, port,
                   init_user_list=[], recv_list=[], sent_ack_cnt=0):
        self.id = user_id
        self.addr = addr
        self.port = port
        self.init_user_list = init_user_list
        self.recv_list = recv_list
        self.sent_ack_cnt = sent_ack_cnt
        self.server = None 
        self.client = None

        # init 
        self.is_in_init = False

    def run_init(self, with_val=None, is_listening=False):
        """
        setup the HIBE system with secret sharing
        """
        if with_val:
            self.recv_list.append(with_val)
            print(self.recv_list)

        if self.is_in_init:
            # if is in init, just add the val into the list
            return 
        
        print("begin running initialization")
        self.is_in_init = True 

        # at the beginning, we should set up a server for
        # receiving the desired packets
        if not is_listening:
            self.server = Server(self)
            
            t = threading.Thread(target=self.server.run)
            t.start()

        # setup the client 
        self.client = Client(self)

        init_user_list = self.init_user_list
        if not init_user_list:
            raise UserError("The init cannot be invoked without the top users")

        # round one

        # sz + 1 == the number of top users
        sz = len(init_user_list)  
        co_cnt = sz + 1          
        # generate a polynomial at first
        poly = SS_new_rand_poly(co_cnt)


        # send the values while receiving 
        while len(self.recv_list) < sz or self.sent_ack_cnt < sz:
            for user in init_user_list:
                addr = user.addr 
                port = user.port 

                packet = Packet.make_init_one(poly, co_cnt, user.id)
                data = packet.to_bytes()

                action = Action()
                action.type = Action.ActionType.SEND
                action.payload = [data]

                t = threading.Thread(target=self.client.run_send, args=(addr, port, action))
                t.start()

            time.sleep(10)

        # round 1 finished, in round 2, shares will be sent among users
        print("round 2")

        # clear the related data
        self.is_in_init = False
        self.sent_ack_cnt = 0
        self.recv_list = []

class UserError(Exception):
    def __init__(self, err='Error in Client Module'):
        Exception.__init__(self, err)
