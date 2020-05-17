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

class User(object):
    """class presenting users in the network

    Attributes:
        id: the identification 
        addr: the IP address 
        port: the port on which the user is running 
    """

    def __init__(self, user_id, addr, port):
        self.id = user_id
        self.addr = addr 
        self.port = port


