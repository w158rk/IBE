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

import socket 


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

    def run_run(self):
        pass 

    def gen_action_from_data(self):
        pass

    def run_send(self, addr, port, action):
        if not addr or not port:
            raise UserError("Unknown target for SEND")

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        srv_addr = (addr, port)
        sock.connect(srv_addr)

        try:
            while True:
                if not action:
                    break
                print(action.type, ", ", action.payload)
                if action.type == Action.ActionType.ABORT:
                    # TODO(wrk): log some error information
                    break
                if action.type == Action.ActionType.EXIT:
                    break
                if action.type == Action.ActionType.SEND:
                    print("send: ", action.payload)
                    sock.sendall(action.payload)
                if action.type == Action.ActionType.RUN:
                    # TODO(wrk): Is this line possible?
                    self.run_run(action)

                data = sock.recv(BUFFER_SIZE)
                print("received: ", data)
                action = self.gen_action_from_data(data)

        except socket.error as e:
            print("Socket Error: %s" % str(e))
        except Exception as e:
            print("Other exception: %s" % str(e))
        finally:
            sock.close()

class UserError(Exception):
    def __init__(self, err='Error in Client Module'):
        Exception.__init__(self, err)
