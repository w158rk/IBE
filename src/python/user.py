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
from init import *
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
                   init_user_list=[], recv_lists=None, sent_ack_cnts=[0,0,0]):
        self.id = user_id
        self.addr = addr
        self.port = port
        self.init_user_list = init_user_list
        if not recv_lists:
            self.recv_lists = [set() for i in range(3)] 
        self.sent_ack_cnts = sent_ack_cnts
        self.server = None 
        self.client = None

        # init 
        self.is_in_init = False
        self.share = None
        self.sP = (None, None)

    def cal_share(self):
        """
        calculate the share with formula:
        
                share = (\sum f(x)) * l_x(0)
        """
        id_list = []
        id_list.append(self.id)
        for user in self.init_user_list:
            id_list.append(user.id)
        return SS_cal_share(self.recv_lists[0], id_list)

    def cal_sP(self):
        """
        
        calculate sP1 = \sum share * P1
        calculate sP2 = \sum share * P2
        """
        
        # l1 and l2 for list of sP1 and sP2
        l1 = []
        l2 = []
        for s in self.recv_lists[1]:
            assert(s[EC_POINT_LEN] == 124)
            assert(len(s) == EC_POINT_LEN + 1 + 129)
            l1.append(s[:EC_POINT_LEN])
            l2.append(s[EC_POINT_LEN+1:])

        sP1, sP2 = SS_cal_sP(l1, l2)
        return (sP1, sP2)

    def output_sP(self, sP, mpk_file=b"./mpk"):
        SS_output_sP(sP)

    def run_init(self, with_val=None, is_listening=False):
        """
        setup the HIBE system with secret sharing
        """
        if with_val:
            self.recv_lists[0].add(with_val)

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


        # sz + 1 == the number of top users
        sz = len(init_user_list)  
        co_cnt = sz + 1          

        # generate a polynomial at first
        poly = SS_new_rand_poly(co_cnt)

        ## add f_i(x_i) into the list
        bn = SS_id2num(self.id)
        bn = SS_poly_apply(poly, co_cnt, bn) 
        self.recv_lists[0].add(bn)

        # round one
        # send the values while receiving 
        while len(self.recv_lists[0]) < co_cnt or self.sent_ack_cnts[0] < sz:
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

            time.sleep(2)

        # now we have all the parts for our share
        # it's time to calculate the share with formula:
        # 
        # share = (\sum f(x)) * l_x(0)
        #

        print("cal share")
        share = self.cal_share()
        self.share = share

        # round 1 finished, in round 2, shares will be sent among users
        print("round 2")

        # first, add the share_i * P1 & share_i * P2 in the list
        point = SS_cal_xP(share)
        self.recv_lists[1].add(point)

        while len(self.recv_lists[1]) < co_cnt or self.sent_ack_cnts[1] < sz:
            for user in init_user_list:
                addr = user.addr 
                port = user.port 

                packet = Packet.make_init_2(point)
                data = packet.to_bytes()

                action = Action()
                action.type = Action.ActionType.SEND
                action.payload = [data]

                t = threading.Thread(target=self.client.run_send, args=(addr, port, action))
                t.start()

            time.sleep(2)

        sP = self.cal_sP()              # a tuple
        self.sP = sP
        self.output_sP(sP)
        

        # clear the related data
        self.is_in_init = False
        self.sent_ack_cnts = [0, 0, 0]
        for s in self.recv_lists:
            s.clear()


class UserError(Exception):
    def __init__(self, err='Error in Client Module'):
        Exception.__init__(self, err)
