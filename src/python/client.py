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
    Client: present a client
    ClientTest: test for client

Functions:
    main: run a test client

'''

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

_valid_actions = {
    "init": "invoke an initialization",
    "sk": "request for the private key",
    "comm": "initialize a secret session inter-domain",
    "comm-no-auth": "initialize a secret session in a domain"
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
        if packet.type == Packet.PacketType.INIT_R1_ACK:
            print("receive ACK")
            self.user.sent_ack_cnts[0] += 1

        if packet.type == Packet.PacketType.INIT_R2_ACK:
            print("receive ACK")
            self.user.sent_ack_cnts[1] += 1

        if packet.type == Packet.PacketType.INIT_R3_ACK:
            print("receive ACK")
            self.user.sent_ack_cnts[2] += 1

        if packet.type == Packet.PacketType.SK_RESPOND_INIT:

            # store the global mpk
            global_mpk = packet.vals[0]
            with open(self.user.global_mpk_file, "wb") as f:
                f.write(global_mpk)

            # store the mpk
            mpk = packet.vals[1]
            with open(self.user.local_mpk_file, "wb") as f:
                f.write(mpk)

            # then we should send the random key
            # let the user generate a key, for a client
            # there is no need to bind anything in client end
            # just set the user's key
            user = self.user
            key = user.generate_sym_key()
            user.sm4_key = key

            packet = Packet.make_sk_request_key_plain(key=key, user_id=user.id)
            plain_text = packet.to_bytes()

            user_id = user.parent.id
            cipher = user.ibe_encrypt(mode="local", m=plain_text, user_id=user_id)
            packet = Packet.make_sk_request_key_sec(cipher=cipher)

            action = Action()
            action.type = Action.ActionType.SEND
            action.payload = [packet.to_bytes()]

            # encrypt the packet with IBE

        if packet.type == Packet.PacketType.SK_RESPOND_KEY_SEC:

            # get the sec_sk
            cipher = packet.vals[0]

            user = self.user
            key = user.sm4_key

            # decrypt to get the sk
            m = user.sm4_dec(key=key, c=cipher)
            packet = Packet.from_bytes(m)

            # output sk
            sk = packet.vals[0]
            sk_len = packet.vals[1]
            sk_len = bytes2int(sk_len)
            sk = sk[:sk_len]
            assert len(sk) == sk_len
            user.output_sk(sk, mode="local")

            # The rest of the packet is all the certificate files
            # Store them one by one
            certs = []
            cert_files = []

            for cert, cert_len in zip(packet.vals[2:], packet.lens[2:]):

                assert len(cert) == cert_len
                cert = Certificate.from_bytes(cert)
                certs.append(cert)
                if cert.payload.aud == bytes2str(user.id):
                    cert_file = user.certificate_file
                else:
                    cert_file = "cert-" + cert.payload.aud + ".conf"
                cert_files.append(cert_file)

            user.cert = certs

            # ATTENTION: A FILENAME MUST BE ASSIGNED TO THE CERTIFICATE, THERE IS NO CHECK
            # IT MIGHT LEAD TO SOME OTHER ERROR IF THE FILENAME IS NOT GIVEN
            for i in range(len(certs)-1):
                certs[i].payload.parent.filename = cert_files[i+1]
            
            for cert, cert_file in zip(certs, cert_files):
                user.output_cert(cert.to_json(with_filename=True), cert_file)

            time_end = time.time()
            time_start = user.time
            print('sk totally cost', time_end-time_start)
     
        if packet.type == Packet.PacketType.COMM_RESPOND_INIT:
            time_start = time.time()
            target_id = packet.vals[1]
            server_id = packet.vals[2]
            server_mpk = packet.vals[3]
            key_mode = packet.vals[4]
            # first, check the parameters
            user = self.user
            assert target_id==user.id 
            assert key_mode in {b"sm4", b"IOT"}

            # Then check the validation of mpk
            certs = []
            for certbytes, certlen in zip(packet.vals[5:], packet.lens[5:]):
                assert len(certbytes) == certlen
                cert = Certificate.from_bytes(certbytes)
                certs.append(cert)

            if not user.check_mpk(server_mpk, certs):
                action = Action()
                action.type = Action.ActionType.SEND
                packet = Packet()
                packet.type = Packet.PacketType.COMM_REFUSE
                action.payload = packet.to_bytes()
                return action

            # output the received certificates
            user.output_certs(certs)

            # generate a random key and send it to the server
            key = urandom(16)
            user.key = key
            if key_mode == b'sm4':
                key_mes = key
            elif key_mode == b'IOT':
                key_mes = self.make_key(KEY_DUR_TIME, key)
                user.IOT_key = key_mes
            else:
                print("KeyModeError!")

            packet = Packet.make_key_request_plain(des_id=server_id, src_id=target_id, key=key_mes, key_mode=key_mode)
            plain_text = packet.to_bytes()

            cipher = user.ibe_encrypt(mode="comm", m=plain_text, user_id=server_id, mpk=server_mpk)
            sign = user.ibe_sign(mode="local", m=plain_text)
            packet = Packet.make_key_request_sec(cipher=cipher, sign=sign) # default mode = "comm"

            action = Action()
            action.type = Action.ActionType.SEND
            action.payload = [packet.to_bytes()]
            time_end = time.time()
            print('totally cost', time_end-time_start)
            return action

        if packet.type == Packet.PacketType.KEY_RESPOND:
            time_start2 = time.time()
            cipher = packet.vals[2]
            src_id = packet.vals[1]
            key_mode = packet.vals[3]
            user = self.user
            key = user.key
            m = user.sm4_dec(key, cipher)
            if m == b"ACK":
                sm4_key_file = key_mode.decode() + "-" + src_id.decode() + ".conf"
                with open(sm4_key_file, "wb") as f:
                    if key_mode == b'sm4':
                        key_mes = key
                    elif key_mode == b'IOT':
                        key_mes = user.IOT_key
                    f.write(key_mes)
            time_end2 = time.time()
            print('totally cost', time_end2-time_start2)
            time_end = time.time()
            time_start = user.time
            print('comm totally cost', time_end-time_start)

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

        if args.action == "init":
            ret.type = Action.ActionType.RUN
            ret.payload = [b"run_init"]

        if args.action == "sk":
            ret.type = Action.ActionType.SEND
            user = self.user

            time_start = time.time()
            user.time = time_start

            if not user.parent:
                raise ClientError("cannot request for private key if no parent assigned")
            parent = user.parent
            assert parent.id
            assert parent.addr
            assert parent.port
            ret.addr = parent.addr
            ret.port = parent.port

            user_id = user.id
            payload = Packet.make_sk_request_init(user_id)
            ret.payload = [payload.to_bytes()]

        if args.action == "comm":
            # At this point, we don't take into account the size of data in the air (in channel)
            # Just send them! Our current goal is minimize the time of verification
            ret.type = Action.ActionType.SEND
            user = self.user

            time_start = time.time()
            user.time = time_start

            if os.path.exists(self.user.local_mpk_file) and os.path.exists(self.user.local_sk_file):
                pass        # do nothing
            else:
                raise ClientError("please generate your own sk first")
            assert args.comm_addr
            assert args.comm_port
            assert args.comm_id
            assert args.key_mode
            ret.addr = args.comm_addr
            ret.port = args.comm_port
            comm_id = args.comm_id
            comm_id = str2bytes(comm_id)
            key_mode = str2bytes(args.key_mode)

            user_id = user.id
            mpk_file = user.local_mpk_file
            mpk = ibe_read_from_file(mpk_file)

            if user.cert == b'':
                certs = user.input_all_certs()
                certs = [cert.to_bytes() for cert in certs]
                user.cert = certs
            else:
                pass

            payload = Packet.make_comm_request_init(des_id=comm_id, src_id=user_id, mpk=mpk, certs=user.cert, key_mode=key_mode)
            ret.payload = [payload.to_bytes()]

        if args.action == "comm-no-auth":
            # This option is for the case that the user has known that it is 
            # to communicate with who shares the public master key with it  
            # 1. If it communicates with its parent, the mode is in `parent`
            # 2. If it communicates with its siblings, the mode is in `sibling`
            # 3. If it communicates with its children, the mode is in `child`
            # send a packet with type KEY_REQUEST_SEC
            # NOTE: currently, there is no way to distinguish the mode `sibline` and `child` 
            #       so we only provide the mode `parent` and `sibling` for simplicity
            ret.type = Action.ActionType.SEND
            user = self.user

            if os.path.exists(self.user.local_mpk_file) and os.path.exists(self.user.local_sk_file):
                pass        # do nothing
            else:
                raise ClientError("please generate your own sk first")

            assert args.comm_addr
            assert args.comm_port
            assert args.comm_id
            ret.addr = args.comm_addr
            ret.port = args.comm_port
            comm_id = args.comm_id
            comm_id = str2bytes(comm_id)
            key_mode = str2bytes(args.key_mode)
            assert key_mode in {b"sm4", b"IOT"}
            mode = None 

            if comm_id == user.parent.id:
                mode = b"parent"
            else:
                mode = b"sibling"

            # generate a random key and send it to the server
            key = urandom(16)
            user.key = key
            if key_mode == b'sm4':
                key_mes = key
            elif key_mode == b'IOT':
                key_mes = self.make_key(KEY_DUR_TIME, key)
                user.IOT_key = key_mes
            else:
                print("KeyModeError!")

            packet = Packet.make_key_request_plain(des_id=comm_id, src_id=user.id, key=key_mes, key_mode=key_mode)
            plain_text = packet.to_bytes()

            cipher = user.ibe_encrypt(mode="local", m=plain_text, user_id=comm_id)
            sign = user.ibe_sign(mode="local", m=plain_text)
            packet = Packet.make_key_request_sec(mode=mode, cipher=cipher, sign=sign)

            ret.payload = [packet.to_bytes()]
            
        # NOTE: We don't provide the option of single-side authentication for simplicity
        # In fact, it can be true that when Bob's certificate is in Alice's cache, Alice can send 
        # the init packet with a notification saying I trust you. In this way, Bob can generate a 
        # random symmetric key directly and send it to Alice securely without send his certificates 
        # at the first step

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
    parser.add_argument('--id', type=str, default="", dest="comm_id")
    parser.add_argument('--key', type=str, default="sm4", dest="key_mode")

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
