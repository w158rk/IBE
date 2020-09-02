#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

from constant import *
from crypto_c_interface import ibe_read_from_file, ibe_write_to_file, ibe_encrypt
from action import Action
from packet import Packet
from utils import bytes2int, bytes2str, str2bytes
from os import urandom
from auth import Certificate
from key import IOT_key
from wsgiref.handlers import format_date_time
from datetime import datetime, timedelta
from time import mktime

import sys
import socket
import argparse
import threading
import time
import traceback
import os
import sqlite3

_valid_actions = {
    "gen-domain": "generate your own domain",
    "request-domain-cert": "request for the cert",
    "sk": "request for the private key",
    "sec": "encrypt the message",
    "dec": "decrypt the cipher"
}
_config_file = ""


class Client(object):
    """
    Attributes:
        user:   The user on which this client is attached
    """

    def __init__(self, user):
        self.user = user
        user.client = self

    def gen_action_from_data(self, data):
        action = Action()
        packet = Packet.from_bytes(data)

        if packet.type == Packet.PacketType.GEN_DOMAIN_SEC:
            cipher = packet.vals[0]

            user = self.user
            key = user.sm4_key

            m = user.sm4_dec(key=key, c=cipher)
            packet = Packet.from_bytes(m)

            mpk = packet.vals[0]
            msk = packet.vals[1]
            sk = packet.vals[2]

            print(mpk)
            print(msk)
            print(sk)

        if packet.type == Packet.PacketType.CERT_DOMAIN_REQUEST:
            m_cert = packet.vals[0]
            cert = Certificate()
            cert = cert.from_bytes(m_cert)
            print(cert.to_json())

        if packet.type == Packet.PacketType.MAKE_SEC_RESPOND:
            cipher = packet.vals[0]
            print(cipher)
            sm_file = "cipher.conf"
            with open(sm_file, "wb") as f:
                f.write(cipher)

        if packet.type == Packet.PacketType.MAKE_DEC_RESPOND:
            m = packet.vals[0]
            print(m)

        if packet.type == Packet.PacketType.MAKE_SK_RESPOND:
            sk = packet.vals[0]
            print(sk)

        return action

    def gen_action_from_args(self, args):
        """generate Action object from the args the user give when using
            this file

        Args:
            args: arguments given by shell instruction

        Returns:
            the Action object
        """
        ret = Action()

        if args.action == "gen-domain":
            ret.type = Action.ActionType.SEND

            assert args.comm_addr
            assert args.comm_port
            ret.addr = args.comm_addr
            ret.port = args.comm_port

            user = self.user
            sm4_key = urandom(16)
            user.sm4_key = sm4_key
            packet = Packet.gen_domain_request(user_id=b"Server1", key_mode=b'sm4', key=sm4_key)
            ret.payload = [packet.to_bytes()]

        if args.action == "request-domain-cert":
            ret.type = Action.ActionType.SEND

            assert args.comm_addr
            assert args.comm_port
            ret.addr = args.comm_addr
            ret.port = args.comm_port

            mpk_file = "mpk.conf"
            user_mpk = b""
            with open(mpk_file, "rb") as f:
                user_mpk = f.read()

            sk_file = "sk.conf"
            father_sk = b""
            with open(sk_file, "rb") as f:
                father_sk = f.read()

            packet = Packet.gen_domain_cert_requet(user_id=b"Client1", user_mpk=user_mpk, father_id=b"Server1", father_sk=father_sk)
            ret.payload = [packet.to_bytes()]

        if args.action == "sec":
            ret.type = Action.ActionType.SEND

            assert args.comm_addr
            assert args.comm_port
            ret.addr = args.comm_addr
            ret.port = args.comm_port

            mpk_file = "mpk.conf"
            user_mpk = b""
            with open(mpk_file, "rb") as f:
                user_mpk = f.read()

            packet = Packet. make_sec_request(user_id=b"Server1", cert=b'', mpk=user_mpk, m=b'hello')
            ret.payload = [packet.to_bytes()]

        if args.action == "dec":
            ret.type = Action.ActionType.SEND

            assert args.comm_addr
            assert args.comm_port
            ret.addr = args.comm_addr
            ret.port = args.comm_port

            c_file = "cipher.conf"
            cipher = b""
            with open(c_file, "rb") as f:
                cipher = f.read()

            sk_file = "sk.conf"
            sk = b""
            with open(sk_file, "rb") as f:
                sk = f.read()

            packet = Packet. make_dec_request(sk=sk, c=cipher)
            ret.payload = [packet.to_bytes()]

        if args.action == "sk":
            ret.type = Action.ActionType.SEND

            assert args.comm_addr
            assert args.comm_port
            ret.addr = args.comm_addr
            ret.port = args.comm_port

            msk_file = "msk.conf"
            msk = b""
            with open(msk_file, "rb") as f:
                msk = f.read()

            packet = Packet. make_sk_request(msk=msk, user_id=b'CLient1')
            ret.payload = [packet.to_bytes()]

        return ret

    def run_run(self, action):
        if action.payload[0] == b"run_init":
            self.user.run_init()

    def make_key(self, dur_time, key=b''):
        IOTkey = IOT_key()

        now = datetime.now()
        delta = timedelta(days=dur_time)
        end = now + delta
        end_stamp = mktime(end.timetuple())
        IOTkey.end_time = format_date_time(end_stamp)

        IOTkey.key = key
        key_mes = IOTkey.to_bytes()

        return key_mes

    def run_send(self, addr, port, action):
        """
        send data to addr:port

        Ensure:
            the list action.payload only contain the data to be sent
        """

        if not addr or not port:
            raise ClientError("Unknown target for SEND")

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        srv_addr = (addr, port)
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
                    assert (len(action.payload) == 1)
                    # print("send: ", action.payload[0])
                    sock.sendall(action.payload[0])
                if action.type == Action.ActionType.RUN:
                    # TODO(wrk): Is this line possible?
                    self.run_run(action)

                data = sock.recv(RECEIVE_BUFFER_SIZE)
                # print("received: ", data)
                print("data len: ", len(data))
                action = self.gen_action_from_data(data)

        except socket.error as e:
            print("Socket Error: %s" % str(e))
        except AssertionError as e:
            traceback.print_exc()
        except Exception as e:
            traceback.print_exc()
        finally:
            sock.close()

    def run(self, srv_host=None, srv_port=None, action=None, args=None):
        """
        do the actual behavior as the action or args identified

        neither srv_host nor sev_port should be None if action.type = SEND
        """

        if args:
            action = self.gen_action_from_args(args)

        if action.type == Action.ActionType.SEND:
            if srv_host and srv_port:
                self.run_send(srv_host, srv_port, action)
            elif action.addr and action.port:
                self.run_send(action.addr, action.port, action)
            else:
                raise ClientError("No address to send")
        if action.type == Action.ActionType.RUN:
            self.run_run(action)


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

    def __init__(self, user_id=b"Client", addr="0.0.0.0", port=10011,
                 srv_addr="localhost", srv_port=10010, args=None):
        self.user_id = user_id
        self.addr = addr
        self.port = port
        self.srv_addr = srv_addr
        self.srv_port = srv_port
        self.args = args

    def test_client_run(self):
        import user
        usr = user.User(self.user_id, self.addr, self.port)
        client = Client(usr)
        args = self.args
        args.action = "sk"
        client.run(self.srv_addr, self.srv_port, args=args)

    def test_client_init(self):
        import user
        server = {
            "id": "Server1",
            "ip_address": self.srv_addr,
            "port": self.srv_port,
            "parent": None
        }
        if _config_file:
            usr = user.User(config_file=_config_file)
        else:
            usr = user.User(self.user_id, self.addr, self.port, top_user_list=[server])
        client = Client(usr)
        args = self.args
        args.action = "init"
        client.run(args=args)

    def test_all(self):
        # self.test_client_run()
        self.test_client_init()


class ClientError(Exception):
    def __init__(self, err='Error in Client Module'):
        Exception.__init__(self, err)


def main():
    parser = argparse.ArgumentParser(description="IBE Client")
    parser.add_argument("--server-ip", action="store", dest="srv_addr",
                        type=str, default="localhost")
    parser.add_argument("--server-port", action="store", dest="srv_port",
                        type=int, default=10010)
    parser.add_argument("--action", dest="action", default="sk",
                        choices=_valid_actions.keys(),
                        help="the valid actions are: %s" % str(_valid_actions))
    parser.add_argument('-c', type=str, nargs="?", default="",
                        dest="config_file", help='configuration file')
    parser.add_argument('--addr', type=str, default="", dest="comm_addr")
    parser.add_argument('--port', type=int, default=0, dest="comm_port")

    _args = parser.parse_args()
    global _config_file
    _config_file = _args.config_file

    import user
    usr = None
    if _config_file:
        usr = user.User(config_file=_config_file)
    client = Client(usr)
    client.run(args=_args)

    f_test = False
    if f_test:
        client_test = ClientTest(srv_addr=_args.srv_addr, srv_port=_args.srv_port,
                                 args=_args)
        client_test.test_all()


if __name__ == "__main__":
    main()
