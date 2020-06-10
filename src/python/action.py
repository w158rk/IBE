#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

'''
@File    :   action.py
@Time    :   2020/05/17 16:09:07
@Author  :   Ruikai Wang
@Version :   1.0
@Contact :   wrk15835@gmail.com
@License :   Copyright (c) 2020 Ruikai Wang
@Desc    :   Define the classes to represent a network action
'''

from enum import Enum


class Action(object):
    """Class to represent a network action

    Attributes:
        type: the type of the action, should be one of SEND, ABORT, EXIT, SEND_AND_EXIT
        payload: the data to be sent, array
        addr: for SEND
        port: for SEND
    """

    class ActionType(Enum):
        SEND = 1
        ABORT = 2       # abort the session
        EXIT = 3        # exit normally
        SEND_AND_EXIT = 4
        RUN = 5
        SEND_AND_RUN = 6

    def __init__(self, action_type=ActionType.ABORT, payload=[], 
                    addr=None, port=None):
        self.type = action_type
        self.payload = payload

