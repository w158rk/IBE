#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

'''
@File    :   server.py
@Time    :   2020/05/17 15:55:01
@Author  :   Ruikai Wang
@Version :   1.0
@Contact :   wrk15835@gmail.com
@License :   Copyright (c) 2020 Ruikai Wang
@Desc    :   classes and functions for a server.

Literally, a server listens on a port, receives packets and makes replies.
The logic about handling the packets is not defined in this file, only
basic send/recv functions are defined here. A interface for the handling
function exists.
'''

from action import Action
from packet import Packet
from utils import int2bytes
from auth import Certificate
from crypto_c_interface import ibe_read_from_file, ibe_write_to_file
from auth import Certificate
from wsgiref.handlers import format_date_time
from datetime import datetime, timedelta
from time import mktime
from constant import RECEIVE_BUFFER_SIZE

import sys
import socket
import threading
import argparse
import traceback
import os


_config_file = ""


class Server(object):
    """class representing a server

    Attributes:
        MAX_NUM_CLIENTS: the maximum number of accepted clients
        num_clients: the current number of clients

    Functions:
        run(): the main function of the server
    """

    def __init__(self, user):
        self.user = user
        user.server = self
        self.MAX_NUM_CLIENTS = 10
        self.num_clients = 0

    def gen_action_from_data(self, data):
        """this is an interface for handling the protocol packets.

        Args:
            data: the received byte stream
        """

        action = Action()
        if data == b"sk":
            action.type = Action.ActionType.SEND_AND_EXIT
            action.payload = b"sk received"
            return action
        try:
            packet = Packet.from_bytes(data)
        except Exception:
            packet = None

        if not packet:
            return action

        if packet.type == Packet.PacketType.INIT_R1:
            # add the payload into the recv_list

            run_action = Action()
            run_action.type = Action.ActionType.RUN
            run_action.payload = [b"run_init", packet.vals[0]]

            send_action = Action()
            send_action.type = Action.ActionType.SEND
            send_action.payload = Packet(Packet.PacketType.INIT_R1_ACK).to_bytes()

            action.type = Action.ActionType.SEND_AND_RUN
            action.payload = [send_action, run_action]

        if packet.type == Packet.PacketType.INIT_R1_ACK:
            print("receive ACK")

        if packet.type == Packet.PacketType.INIT_R2:
            # add the payload into the recv_list

            action.type = Action.ActionType.SEND
            action.payload = Packet(Packet.PacketType.INIT_R2_ACK).to_bytes()
            self.user.recv_lists[1].add(packet.vals[0])

        if packet.type == Packet.PacketType.INIT_R2_ACK:
            print("receive ACK")
            self.user.sent_ack_cnts[1] += 1

        if packet.type == Packet.PacketType.INIT_R3:
            # add the payload into the recv_list

            action.type = Action.ActionType.SEND
            action.payload = Packet(Packet.PacketType.INIT_R3_ACK).to_bytes()
            self.user.recv_lists[2].add(packet.vals[0])

        if packet.type == Packet.PacketType.INIT_R3_ACK:
            print("receive ACK")
            self.user.sent_ack_cnts[2] += 1

        if packet.type == Packet.PacketType.SK_REQUEST_INIT:
            # send system parameter and TODO(wxy): certificate

            # check the system parameters
            if os.path.exists(self.user.admin_mpk_file) and os.path.exists(self.user.admin_msk_file) and os.path.exists(self.user.admin_sk_file):
                pass        # do nothing
            else:
                self.run_gen_sys()

            # check the certificate
            if self.user.parent is None and not os.path.exists(self.user.certificate_file):
                self.run_gen_auth()

            action = Action()
            action.type = Action.ActionType.SEND
            mpk_file = self.user.admin_mpk_file
            packet = Packet.make_sk_respond_init(mpk_file=mpk_file)
            action.payload = packet.to_bytes()

        if packet.type == Packet.PacketType.SK_REQUEST_KEY_SEC:
            # send sk and sig to client

            cipher = packet.vals[0]

            user = self.user
            m = user.ibe_decrypt(mode="admin", c=cipher)
            packet = Packet.from_bytes(m)

            sm4_key = packet.vals[0]
            client_id = packet.vals[1]

            client_sk = self.user.ibe_extract(mode="admin", c_id=client_id)
            assert client_sk
            sk_len = len(client_sk)
            sk_len = int2bytes(sk_len, 4)

            client_sig = self.gen_client_sig(client_id, client_sk)
            sig_len = len(client_sig)
            sig_len = int2bytes(sig_len, 4)
            packet = Packet.make_sk_respond_key_plain(client_sk, sk_len, client_sig, sig_len)

            plain_text = packet.to_bytes()

            cipher = user.sm4_enc(key=sm4_key, m=plain_text)
            packet = Packet.make_sk_respond_key_sec(cipher=cipher)

            action.type = Action.ActionType.SEND
            action.payload = packet.to_bytes()

        if packet.type == Packet.PacketType.COMM_REQUEST_INIT:

            des_id = packet.vals[0]
            src_id = packet.vals[1]
            src_father_id = packet.vals[2]
            src_mpk = packet.vals[3]
            src_sig = packet.vals[4]

            user = self.user
            if user.parent is None:
                father_id = b"null"
            else:
                father_id = user.parent.id

            mpk_file = user.local_mpk_file
            mpk = ibe_read_from_file(mpk_file)

            sig_file = user.certificate_file
            user_sig = ibe_read_from_file(sig_file)

            admin = 0
            if os.path.exists(self.user.admin_mpk_file):
                admin = 1

            if admin == 1:
                adm_mpk_file = user.admin_mpk_file
                adm_mpk = ibe_read_from_file(adm_mpk_file)

            if user.id != des_id:
                str1 = "des_id = "
                str1 = str1 + des_id.decode()
                str2 = "user_id = "
                str2 = str2 + user.id.decode()
                print(str1)
                print(str2)
                print("SendError!")

            elif src_father_id == father_id and src_mpk == mpk:
                # comm in the same domin
                des_id = src_id
                src_id = user.id
                packet = Packet.make_comm_respond_init(mode=b'1', des_id=des_id, src_id=src_id, mpk=mpk, sig=user_sig)

                action.type = Action.ActionType.SEND
                action.payload = packet.to_bytes()

            elif admin == 1 and src_father_id == user.id and src_mpk == adm_mpk:
                # comm with father node
                des_id = src_id
                src_id = user.id
                packet = Packet.make_comm_respond_init(mode=b'3', des_id=des_id, src_id=src_id, mpk=adm_mpk, sig=user_sig)

                action.type = Action.ActionType.SEND
                action.payload = packet.to_bytes()

            elif src_father_id == father_id and src_mpk != mpk:
                print("MPKERROR!")
            elif src_father_id != father_id and src_mpk == mpk:
                print("FatherIDERROR!")
            else:
                # comm cross the domin
                # TODO: sig certification

                if user.sig_verify(client_id=src_id, sig=src_sig):
                    print("Certification Verify done!")
                    src_mpk_file = "mpk-" + src_id.decode() + ".conf"
                    ibe_write_to_file(src_mpk, src_mpk_file)

                    des_id = src_id
                    src_id = user.id
                    packet = Packet.make_comm_respond_init(mode=b'2', des_id=des_id, src_id=src_id, mpk=mpk, sig=user_sig)

                    action.type = Action.ActionType.SEND
                    action.payload = packet.to_bytes()

                else:
                    print("SigError!")

        if packet.type == Packet.PacketType.KEY_REQUEST_SEC:

            mode = packet.vals[0]
            cipher = packet.vals[1]
            sign = packet.vals[2]

            user = self.user
            if mode == b'1' or mode == b'2':
                m = user.ibe_decrypt(mode="local", c=cipher)
            elif mode == b'3':
                m = user.ibe_decrypt(mode="admin", c=cipher)

            packet = Packet.from_bytes(m)

            des_id = packet.vals[0]
            src_id = packet.vals[1]
            sm4_key = packet.vals[2]

            if mode == b'1':
                verify = user.ibe_verify(mode="local", m=m, sm=sign, user_id=src_id)
            elif mode == b'2':
                src_mpk_file = "mpk-" + src_id.decode() + ".conf"
                verify = user.ibe_verify(mode="comm", m=m, sm=sign, user_id=src_id, filename=src_mpk_file)
            elif mode == b'3':
                src_mpk_file = "mpk-" + src_id.decode() + ".conf"
                verify = user.ibe_verify(mode="admin", m=m, sm=sign, user_id=src_id)

            if verify:
                sm4_key_file = "sm4-" + src_id.decode() + ".conf"
                with open(sm4_key_file, "wb") as f:
                    f.write(sm4_key)
            else:
                print("VerifyError!")

            cipher = user.sm4_enc(key=sm4_key, m=b"ACK")
            packet = Packet.make_key_respond(des_id=src_id, src_id=des_id, m=cipher)

            action.type = Action.ActionType.SEND
            action.payload = packet.to_bytes()

        return action

    def run(self):

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # bind the address and port
        srv_addr = (self.user.addr, self.user.port)
        sock.bind(srv_addr)

        sock.listen(self.MAX_NUM_CLIENTS)

        print("server is running")
        while True:
            conn, addr = sock.accept()
            t = threading.Thread(target=self.handle_thread, args=(conn, addr))
            t.start()

    def run_gen_sys(self):
        print("generate the system")
        user = self.user
        user.ibe_setup(mode="admin")
        sk = user.ibe_extract(mode="admin", c_id=user.id)
        user.output_sk(sk, mode="admin")

    def run_gen_auth(self):
        print("generate the certificate")
        user = self.user
        certif = Certificate()

        certif.payload.iss = user.id
        certif.payload.aud = user.id

        exp = datetime.now()
        exp += timedelta(days=365)
        stamp = mktime(exp.timetuple())

        certif.payload.exp = format_date_time(stamp)
        certif.payload.mpk = user.input_mpk(mode="global")
        certif.payload.parent = "null"

        certif.make_sig(user.input_sk(mode="global"))

        certif_mes = certif.to_bytes()

        certif_file = user.certificate_file
        ibe_write_to_file(certif_mes, certif_file)

    def gen_client_sig(self, client_id=b"", client_sk=b""):
        print("generate the client's certificate")
        user = self.user
        certif_file = user.certificate_file
        server_sig = ibe_read_from_file(certif_file)

        certif = Certificate()

        certif.payload.iss = user.id
        certif.payload.aud = client_id

        exp = datetime.now()
        exp += timedelta(days=365)
        stamp = mktime(exp.timetuple())

        certif.payload.exp = format_date_time(stamp)
        certif.payload.mpk = user.input_mpk(mode="admin")
        certif.payload.parent = server_sig

        certif.make_sig(user.input_sk(mode="admin"))

        client_sig = certif.to_bytes()
        return client_sig

    def run_run(self, action):
        if action.payload[0] == b"run_init":
            _, val = action.payload
            self.user.run_init(with_val=val, is_listening=True)

    def handle_thread(self, sock, addr, user=None):
        """the main function of handle thread

        Here we get byte stream from network, makes corresponding replies,
        sometimes maintains a "session"
        """

        try:
            while True:
                data = sock.recv(RECEIVE_BUFFER_SIZE)
                if data:

                    # TODO(wrk): maybe generate some log information

                    print("received: ", data)
                    action = self.gen_action_from_data(data)
                    if action:
                        if action.type == Action.ActionType.EXIT:
                            break
                        if action.type == Action.ActionType.ABORT:
                            # TODO(wrk): log some error infomation
                            break
                        if action.type == Action.ActionType.SEND:
                            print("send: ", action.payload)
                            sock.send(action.payload)
                        if action.type == Action.ActionType.SEND_AND_EXIT:
                            print("send: ", action.payload)
                            sock.send(action.payload)
                            break
                        if action.type == Action.ActionType.RUN:
                            if action.payload[0] == b"run_init":
                                self.run_run(action)
                        if action.type == Action.ActionType.SEND_AND_RUN:
                            send_action, run_action = action.payload
                            sock.send(send_action.payload)
                            self.run_run(run_action)
                        if action.type == Action.ActionType.RUN_AND_SEND:
                            run_action, send_action = action.payload
                            self.run_run(run_action)
                            sock.send(send_action.payload)

            sock.close()

        except socket.error as e:
            print("Socket error: %s" % str(e))
        except Exception as e:
            traceback.print_exc()


class ServerTest(object):
    """the class for testing the functionality of Server

    Attributes:
        server

    Tests:
        Server.run
    """

    def __init__(self, user_id=b"Server", addr="0.0.0.0", port=10010):
        from user import User
        server2 = User(b"Client", "127.0.0.1", 10011)

        if _config_file:
            self.user = User(config_file=_config_file)
        else:
            self.user = User(user_id, addr, port, top_user_list=[server2])
        self.server = Server(self.user)

    def test_server_run(self):
        self.server.run()

    def test_all(self):
        self.test_server_run()


def main():
    parser = argparse.ArgumentParser(description='run an IBE server')
    parser.add_argument('-c', type=str, nargs="?",
                        dest="config_file", help='configuration file')
    args = parser.parse_args()
    global _config_file
    _config_file = args.config_file

    server_test = ServerTest()
    server_test.test_all()


if __name__ == "__main__":
    main()
