#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

import json

from wsgiref.handlers import format_date_time
from datetime import datetime, timedelta
from time import mktime
from base64 import b64encode, b64decode
from utils import str2bytes, bytes2str
from constant import KEY_DUR_TIME


def global_to_json(obj):
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, indent=4)


def global_from_json(json_str):
    return json.loads(json_str, encoding="utf-8")


class IOT_key:

    _valid_attrs = [
        "time_stamp",
        "end_time",
        "key"
    ]

    def __init__(self,
                 time_stamp="",
                 end_time="",
                 key=""):

        now = datetime.now()
        stamp = mktime(now.timetuple())

        if not time_stamp:
            time_stamp = format_date_time(stamp)

        self.time_stamp = time_stamp
        self.end_time = end_time
        self.key = key

    @classmethod
    def from_json(cls, json_str):
        ret = cls()
        obj = global_from_json(json_str)
        for attr in obj:
            assert attr in cls._valid_attrs
            val = obj[attr]
            if attr == 'key':
                val = b64decode(val)
            ret.__setattr__(attr, val)
        return ret

    @classmethod
    def from_bytes(cls, byte_str):
        obj = b64decode(byte_str)
        obj = bytes2str(obj)
        return cls.from_json(obj)

    def to_json(self):
        obj = {}
        for attr in self._valid_attrs:

            """
            obj[attr] = getattr(self, attr).decode()
            """

            val = getattr(self, attr)
            if attr == 'key':
                val = b64encode(val)
            if type(val) == bytes:
                val = bytes2str(val)
            obj[attr] = val

        return global_to_json(obj)

    def to_bytes(self):
        obj = self.to_json()
        obj = str2bytes(obj)
        return b64encode(obj)
