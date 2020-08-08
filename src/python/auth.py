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

from wsgiref.handlers import format_date_time
import email.utils as eut
from datetime import datetime
from time import mktime
from base64 import b64encode, b64decode
from utils import str2bytes, bytes2str
from crypto_c_interface import ibe_sign, ibe_verify


def global_to_json(obj):
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, indent=4)


def global_from_json(json_str):
    return json.loads(json_str, encoding="utf-8")


class Certificate:

    _valid_attrs = [
        "header",
        "payload",
        "sig"
    ]

    class Header:
        _valid_attrs = [
            "type",
            "alg"
        ]

        def __init__(self, htype='hwt', alg='sm9'):

            self.type = htype
            self.alg = alg

        @classmethod
        def from_json(cls, json_str):
            ret = cls()
            obj = global_from_json(json_str)
            for attr in obj:
                assert attr in cls._valid_attrs
                ret.__setattr__(attr, obj[attr])
            return ret

        @classmethod
        def from_bytes(cls, byte_str):
            obj = b64decode(byte_str)
            obj = bytes2str(obj)
            return cls.from_json(obj)

        def to_json(self, with_filename=False):
            obj = {
                "type": self.type,
                "alg": self.alg
            }

            return global_to_json(obj)

        def to_bytes(self):
            obj = self.to_json()
            obj = str2bytes(obj)
            return b64encode(obj)

    class Payload:
        _valid_attrs = [
            "iss",
            "aud",
            "exp",
            "nbf",
            "iat",
            "mpk",
            "parent"
        ]

        class Parent:
            _valid_attrs = [
                "id",
                "hash"
            ]

            def __init__(self, parent_id="", filename="", dgst=""):
                self.id = parent_id
                self.filename = filename
                self.hash = dgst

            @classmethod
            def from_json(cls, json_str):
                ret = cls()
                obj = global_from_json(json_str)
                for attr in obj:
                    assert attr in cls._valid_attrs or attr == "filename"
                    val = obj[attr]
                    if attr == 'hash':
                        val = b64decode(val)
                    ret.__setattr__(attr, val)
                return ret

            @classmethod
            def from_bytes(cls, byte_str):
                obj = b64decode(byte_str)
                obj = bytes2str(obj)
                return cls.from_json(obj)

            def to_json(self, with_filename=False):
                obj = {}
                for attr in self._valid_attrs:

                    """
                    obj[attr] = getattr(self, attr).decode()
                    """

                    val = getattr(self, attr)
                    if attr == 'hash':
                        val = b64encode(val)
                    if type(val) == bytes:
                        val = bytes2str(val)
                    obj[attr] = val

                if with_filename:
                    obj["filename"] = self.filename

                return global_to_json(obj)

            def to_bytes(self):
                obj = self.to_json()
                obj = str2bytes(obj)
                return b64encode(obj)

        def __init__(self,
                     iss="",
                     aud="",
                     exp=None,
                     nbf=None,
                     iat=None,
                     mpk="",
                     parent=None):

            now = datetime.now()
            stamp = mktime(now.timetuple())

            if not exp:
                exp = format_date_time(stamp)
            if not nbf:
                nbf = format_date_time(stamp)
            if not iat:
                iat = format_date_time(stamp)
            if not parent:
                parent = self.Parent()

            self.iss = iss
            self.aud = aud
            self.exp = exp
            self.nbf = nbf
            self.iat = iat
            self.mpk = mpk
            self.parent = parent

        @classmethod
        def from_json(cls, json_str):
            ret = cls()
            obj = global_from_json(json_str)
            for attr in obj:
                assert attr in cls._valid_attrs
                val = obj[attr]
                if attr == 'mpk':
                    val = b64decode(val)
                if attr == 'parent' and val:
                    val = cls.Parent.from_json(global_to_json(val))
                ret.__setattr__(attr, val)
            return ret

        @classmethod
        def from_bytes(cls, byte_str):
            obj = b64decode(byte_str)
            obj = bytes2str(obj)
            return cls.from_json(obj)

        def to_json(self, with_filename=False):
            obj = {}
            for attr in self._valid_attrs:

                """
                obj[attr] = getattr(self, attr).decode()
                """

                val = getattr(self, attr)
                if attr == 'mpk':
                    val = b64encode(val)
                if type(val) == bytes:
                    val = bytes2str(val)
                if attr == "parent" and val:
                    val = val.to_json(with_filename)
                    val = global_from_json(val)
                obj[attr] = val

            return global_to_json(obj)

        def to_bytes(self):
            obj = self.to_json()
            obj = str2bytes(obj)
            return b64encode(obj)

    class Signature:
        _valid_attrs = [
            "header",
            "payload",
            "sig"
        ]

        def __init__(self,
                     header="",
                     payload="",
                     sig=""):
            self.header = header
            self.payload = payload
            self.sig = sig

        @classmethod
        def from_json(cls, json_str):
            ret = cls()
            obj = global_from_json(json_str)
            for attr in obj:
                assert attr in cls._valid_attrs
                val = obj[attr]
                if attr == 'sig':
                    val = b64decode(val)
                ret.__setattr__(attr, val)
            return ret

        @classmethod
        def from_bytes(cls, byte_str):
            obj = b64decode(byte_str)
            obj = bytes2str(obj)
            return cls.from_json(obj)

        def to_json(self, with_filename=False):
            obj = {}
            for attr in self._valid_attrs:

                """
                obj[attr] = getattr(self, attr).decode()
                """

                val = getattr(self, attr)
                if attr == 'sig' and val:
                    val = b64encode(val)
                if type(val) == bytes:
                    val = bytes2str(val)
                obj[attr] = val

            return global_to_json(obj)

        def to_bytes(self):
            obj = self.to_json()
            obj = str2bytes(obj)
            return b64encode(obj)

    def __init__(self,
                 header=None,
                 payload=None,
                 sig=None):
        if not header:
            header = Certificate.Header()
        if not payload:
            payload = Certificate.Payload()
        if not sig:
            sig = Certificate.Signature()

        self.header = header
        self.payload = payload
        self.sig = sig

    def make_sig(self, sk=b""):
        header = self.header.to_bytes()
        payload = self.payload.to_bytes()
        sig = Certificate.Signature()
        sig.header = ""
        sig.payload = ""
        m = b".".join([header, payload])
        digest = ibe_sign(m, sk)
        sig.sig = digest
        self.sig = sig

    @classmethod
    def from_json(cls, json_str):
        ret = cls()
        obj = global_from_json(json_str)

        ret.header = cls.Header.from_json(global_to_json(obj['header']))
        ret.payload = cls.Payload.from_json(global_to_json(obj['payload']))
        ret.sig = cls.Signature.from_json(global_to_json(obj['sig']))

        return ret

    @classmethod
    def from_bytes(cls, byte_str):
        obj = b64decode(byte_str)
        obj = bytes2str(obj)
        return cls.from_json(obj)

    def to_json(self, with_filename=False):
        obj = {}
        for attr in self._valid_attrs:

            """
            obj[attr] = getattr(self, attr).decode()
            """
            val = getattr(self, attr)
            val = val.to_json(with_filename)
            obj[attr] = global_from_json(val)

        return global_to_json(obj)

    def to_bytes(self):
        obj = self.to_json()
        obj = str2bytes(obj)
        return b64encode(obj)

    def verify(self, mpk):
        now = datetime.now()
        exp = datetime(*eut.parsedate(self.payload.exp)[:6])
        if now > exp:
            return False
        nbf = datetime(*eut.parsedate(self.payload.nbf)[:6])
        if now < nbf:
            return False

        header = self.header.to_bytes()
        payload = self.payload.to_bytes()
        m = b'.'.join([header, payload])
        sig = self.sig.sig
        return ibe_verify(m, sig, mpk, str2bytes(self.payload.iss))
