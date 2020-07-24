#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

'''
@File    :   auth.py
@Time    :   2020/07/22 21:35:03
@Author  :   Ruikai Wang 
@Version :   1.0
@Contact :   wrk15835@gmail.com
@License :   Copyright (c) 2020 Ruikai Wang
@Desc    :   The logics for authentication in this system

The structure of certificates is compatible with JWT(https://jwt.io/), there might be 
other more common structure for certificates. We use JWT here for convenience.

Basically, a certificate can be split into three parts:
    - header
    - payload 
    - signature 

# header 
    - type: 'hwt',
    - alg: 'sm9'

# payload 
    - iss: issuer
    - aud: this certificate is oriented for 
    - exp: when the certificate will expire
    - nbf: when the certificate will start to be valid 
    - iat: when the certificate is issued
    - mpk: the mpk the targeted user will use
    - parent: the hash of the parent certificate (how to send the whole series needs to be checked)

# signature
    - header: the base64-encoded header
    - payload: the base64-encoded payload
    - sig: signed on the "header + b'.' + payload"

'''

import json

from base64 import b64encode, b64decode
from utils import str2bytes, bytes2str

def to_json(obj):
    """
    obj should be a list or a dict
    """
    return json.dumps(obj, ensure_ascii=False, encoding='utf-8')

def from_json(json_str):
    return json.loads(json_str, ensure_ascii=False, encoding='utf-8')

class Certificate:
    class Header:
        
        def __init__(self, htype='hwt', alg='sm9'):
            Certificate.Header._valid_attrs = [
                "type", 
                "alg"
            ]
            self.type = htype 
            self.alg = alg 
        
        @classmethod
        def from_json(cls, json_str):
            ret = cls()
            obj = from_json(json_str)
            for attr in obj:
                assert attr in cls._valid_attrs
                ret.__setattr__(attr, obj[attr])
            return ret 
        
        @classmethod
        def from_bytes(cls, byte_str):
            obj = b64decode(byte_str)
            obj = bytes2str(obj)
            return cls.from_json(obj)

        def to_json(self):
            obj = {
                "type": self.type,
                "alg": self.alg
            }

            return to_json(obj)

        def to_bytes(self):
            obj = self.to_json()
            obj = str2bytes(obj)
            return b64encode(obj)          

    
    class Payload:
        pass 

    class Signature:
        pass

    def __init__(self):
        pass
    
    @classmethod
    def from_bytes(cls):
        pass
    
    def to_bytes(self):
        pass