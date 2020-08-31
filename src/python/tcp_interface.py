#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

from action import Action
from packet import Packet
from utils import int2bytes, bytes2str
from auth import Certificate
from crypto_c_interface import ibe_read_from_file, ibe_write_to_file, sm3_hash, ibe_encrypt, ibe_decrypt
from wsgiref.handlers import format_date_time
from datetime import datetime, timedelta
from time import mktime
from constant import RECEIVE_BUFFER_SIZE
from key import IOT_key

import sys
import socket
import threading
import argparse
import traceback
import os
import time
import sqlite3


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

    def gen_action_from_data(self, data, temp_vars=None):
        """this is an interface for handling the protocol packets.

        Args:
            data: the received byte stream
        """

        action = Action()
        if data == b"sk":
            action.type = Action.ActionType.SEND_AND_EXIT
            action.payload = [b"sk received"]
            return action
        try:
            packet = Packet.from_bytes(data)
        except Exception:
            packet = None

        if not packet:
            return action

        if packet.type == Packet.PacketType.GEN_DOMAIN_REQUEST:

            user_id = packet.vals[0]
            key_mode = packet.vals[1]
            key = packet.vals[2]

            user = self.user
            user.ibe_setup(mode="admin")
            user_sk = user.ibe_extract(mode="admin", c_id=user_id)
            user.output_sk(user_sk, mode="admin")
            print("gen-domain finish")

            mpk_file = self.user.admin_mpk_file
            user_mpk = b""
            with open(mpk_file, "rb") as f:
                user_mpk = f.read()

            msk_file = self.user.admin_msk_file
            user_msk = b""
            with open(msk_file, "rb") as f:
                user_msk = f.read()

            packet = Packet.gen_domain_plain(mpk=user_mpk, msk=user_msk, sk=user_sk)
            plain_text = packet.to_bytes()

            if key_mode == b'sm4':
                cipher = user.sm4_enc(key=key, m=plain_text)
            else:
                pass

            packet = Packet.gen_domain_sec(cipher=cipher)
            action.type = Action.ActionType.SEND
            action.payload = [packet.to_bytes()]

        if packet.type == Packet.PacketType.CERT_DOMAIN_REQUEST:
            client_id = packet.vals[0]
            client_mpk = packet.vals[1]

            domain_cert = self.gen_domain_sig(client_id, client_mpk)
            cert_m = domain_cert.to_bytes()

            action = Action()
            action.type = Action.ActionType.SEND
            packet = Packet.make_domain_respond(cert_m)
            action.payload = [packet.to_bytes()]

        if packet.type == Packet.PacketType.MAKE_SEC_REQUEST:
            user_id = packet.vals[0]
            mpk = packet.vals[1]
            cert = packet.vals[2]
            m = packet.vals[3]

            c = ibe_encrypt(user_id=user_id, mpk=mpk, m=m)

            action = Action()
            action.type = Action.ActionType.SEND
            packet = Packet.make_sec_respond(cipher=c)
            action.payload = [packet.to_bytes()]

        if packet.type == Packet.PacketType.MAKE_DEC_REQUEST:
            sk = packet.vals[0]
            c = packet.vals[1]

            m = ibe_decrypt(c=c, sk=sk)

            action = Action()
            action.type = Action.ActionType.SEND
            packet = Packet.make_dec_respond(m=m)
            action.payload = [packet.to_bytes()]

        if packet.type == Packet.PacketType.DOMAIN_REQUEST:
            client_id = packet.vals[0]
            client_mpk = packet.vals[1]

            domain_cert = self.gen_domain_sig(client_id, client_mpk)
            cert_m = domain_cert.to_bytes()

            action = Action()
            action.type = Action.ActionType.SEND
            packet = Packet.make_domain_respond(cert_m)
            action.payload = [packet.to_bytes()]

        if packet.type == Packet.PacketType.SK_REQUEST_INIT:
            # send system parameter and TODO(wxy): certificate

            # check the system parameters
            if os.path.exists(self.user.admin_mpk_file) and os.path.exists(self.user.admin_msk_file) and os.path.exists(self.user.admin_sk_file):
                pass        # do nothing
            else:
                # self.run_gen_sys()
                print("please generate your own domain first")

            # if not self.user.parent and not os.path.exists(self.user.certificate_file):
            #     # top user without certificate file
            #     self.run_gen_auth()

            action = Action()
            action.type = Action.ActionType.SEND
            mpk_file = self.user.admin_mpk_file
            packet = Packet.make_sk_respond_init(mpk_file=mpk_file)
            action.payload = [packet.to_bytes()]

        if packet.type == Packet.PacketType.SK_REQUEST_KEY_SEC:
            # send sk and cert to client

            cipher = packet.vals[0]

            user = self.user
            m = user.ibe_decrypt(mode="admin", c=cipher)
            packet = Packet.from_bytes(m)

            sm4_key = packet.vals[0]
            client_id = packet.vals[1]
            client_addr = packet.vals[2]
            client_port = packet.vals[3]
            cl_id = client_id.decode()
            cl_addr = client_addr.decode()
            cl_port = int().from_bytes(client_port, byteorder='big', signed=True)

            client_list = sqlite3.connect('client_list.db')

            client_list.execute('''CREATE TABLE IF NOT EXISTS CLIENT
                                (ID     CHAR(50)    PRIMARY KEY     NOT NULL,
                                ADDR    CHAR(50),
                                PORT    INT);''')

            client_list.execute("INSERT OR IGNORE INTO CLIENT (ID,ADDR,PORT) \
                                 VALUES ('{}','{}','{}')".format(cl_id, cl_addr, cl_port))

            client_list.commit()
            client_list.close()

            # client_list = sqlite3.connect('client_list.db')
            # cursor = client_list.execute("SELECT ID, ADDR, PORT from CLIENT")
            # for row in cursor:
            #     print(row[0])
            #     print(row[1])
            #     print(row[2])

            client_sk = self.user.ibe_extract(mode="admin", c_id=client_id)
            assert client_sk
            sk_len = len(client_sk)
            sk_len = int2bytes(sk_len, 4)

            cert_list = []

            # append the cert file generated for the next layer
            client_cert = self.gen_client_sig(client_id)
            cert_list.append(client_cert.to_bytes())

            certs = user.input_all_admin_certs()
            for cert in certs:
                certs = cert.to_bytes()
                cert_list.append(certs)

                # get all the certificates of current user
            # cert_file = user.certificate_file
            # while True:
            #     assert os.path.exists(cert_file)
            #     cert = user.input_cert(cert_file)
            #     cert = Certificate.from_json(cert)
            #     cert_list.append(cert.to_bytes())
            #     if not cert.payload.parent:
            #         break
            #     # next certificate name
            #     cert_file = cert.payload.parent.filename

            packet = Packet.make_sk_respond_key_plain(client_sk, sk_len, cert_list)

            plain_text = packet.to_bytes()

            cipher = user.sm4_enc(key=sm4_key, m=plain_text)
            packet = Packet.make_sk_respond_key_sec(cipher=cipher)

            action.type = Action.ActionType.SEND
            action.payload = [packet.to_bytes()]

        if packet.type == Packet.PacketType.COMM_REQUEST_INIT:
            target_id = packet.vals[0]
            client_id = packet.vals[1]
            client_mpk = packet.vals[2]
            key_mode = packet.vals[3]

            # first, check the parameters
            user = self.user
            assert target_id == user.id
            assert key_mode in {b"sm4", b"IOT"}

            # Then check the validation of mpk
            certs = []
            for certbytes, certlen in zip(packet.vals[4:], packet.lens[4:]):
                assert len(certbytes) == certlen
                cert = Certificate.from_bytes(certbytes)
                certs.append(cert)

            if not user.check_mpk(client_mpk, certs):
                action = Action()
                action.type = Action.ActionType.SEND
                packet = Packet()
                packet.type = Packet.PacketType.COMM_REFUSE
                action.payload = [packet.to_bytes()]
                return action

            # The client_mpk is valid, store it in the temperary vars
            temp_vars['mpk'] = client_mpk

            # send the server's mpk and certificate
            # it is relatively like the way in which the client do
            # NOTE(wrk): check its logic if necessary
            user.add_certs_in_cache(certs)

            mpk = user.input_mpk(mode="local")
            time_start2 = time.time()
            if user.cert == b'':
                certs = user.input_all_local_certs()
                certs = [cert.to_bytes() for cert in certs]
                user.cert = certs
            else:
                pass

            time_end2 = time.time()
            print('cost', time_end2-time_start2)

            action = Action()
            action.type = Action.ActionType.SEND
            packet = Packet.make_comm_respond_init(mode=b'2', des_id=client_id,
                                                   src_id=target_id, mpk=mpk, certs=user.cert, key_mode=key_mode)
            action.payload = [packet.to_bytes()]
            return action

        if packet.type == Packet.PacketType.KEY_REQUEST_SEC:
            mode = packet.vals[0]
            cipher = packet.vals[1]
            sign = packet.vals[2]

            user = self.user
            if mode == b'comm' or mode == b'sibling':
                m = user.ibe_decrypt(mode="local", c=cipher)
            elif mode == b'parent':
                m = user.ibe_decrypt(mode="admin", c=cipher)
            else:
                raise Exception()

            packet = Packet.from_bytes(m)
            target_id = packet.vals[0]
            client_id = packet.vals[1]
            key_mes = packet.vals[2]
            key_mode = packet.vals[3]

            assert target_id == user.id
            assert key_mode in {b"sm4", b"IOT"}

            if key_mode == b'sm4':
                sm4_key = key_mes
            elif key_mode == b'IOT':
                key = IOT_key()
                key = key.from_bytes(key_mes)
                sm4_key = key.key

            if mode == b'sibling':
                verify = user.ibe_verify(mode="local", m=m, sm=sign, user_id=client_id)
            elif mode == b'comm':
                verify = user.ibe_verify(mode="comm", m=m, sm=sign, user_id=client_id, mpk=temp_vars['mpk'])
            elif mode == b'parent':
                verify = user.ibe_verify(mode="admin", m=m, sm=sign, user_id=client_id)
            else:
                raise Exception

            if verify:
                sm4_key_file = bytes2str(key_mode) + "-" + bytes2str(client_id) + ".conf"
                with open(sm4_key_file, "wb") as f:
                    f.write(key_mes)
            else:
                print("VerifyError!")

            cipher = user.sm4_enc(key=sm4_key, m=b"ACK")
            packet = Packet.make_key_respond(des_id=client_id, src_id=target_id, m=cipher, key_mode=key_mode)

            action.type = Action.ActionType.SEND
            action.payload = [packet.to_bytes()]

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

    def run_gen_local_auth(self):
        print("generate the local certificate")
        user = self.user
        cert = Certificate()

        cert.payload.iss = None             # top user

        cert.payload.aud = "top-" + user.id.decode()
        cert.payload.top_types = "top"
        cert.payload.admin_types = "local"

        exp = datetime.now()
        exp += timedelta(days=365)
        stamp = mktime(exp.timetuple())

        cert.payload.exp = format_date_time(stamp)
        cert.payload.mpk = user.input_mpk(mode="global")
        cert.payload.parent = None

        user.cert = cert.to_bytes()

        # There is no need for a top user to generate a signature
        # Users trust them with the fact that they own the
        # private keys corresponding to global public master key

        filename = "cert-top-" + user.id.decode() + ".conf"

        user.output_cert(cert=cert.to_json(), ctype="local")
        user.output_cert(cert=cert.to_json(), cert_file=filename)

    def run_gen_admin_auth(self):
        print("generate the admin certificate")
        user = self.user
        cert_file = "cert-top-" + user.id.decode() + ".conf"
        local_cert = user.input_cert(filename=cert_file)
        local_cert = Certificate.from_json(local_cert)

        cert = Certificate()

        cert.payload.iss = "top-" + user.id.decode()
        cert.payload.aud = user.id
        cert.payload.top_types = "non-top"
        cert.payload.admin_types = "admin"

        exp = datetime.now()
        exp += timedelta(days=365)
        stamp = mktime(exp.timetuple())

        cert.payload.exp = format_date_time(stamp)
        cert.payload.mpk = user.input_mpk(mode="admin")
        cert.payload.parent.id = user.id
        cert.payload.parent.filename = "cert-top-" + user.id.decode() + ".conf"
        cert.payload.parent.hash = sm3_hash(local_cert.to_bytes())
        cert.make_sig(user.input_sk(mode="global"))

        user.cert = cert.to_bytes()

        # There is no need for a top user to generate a signature
        # Users trust them with the fact that they own the
        # private keys corresponding to global public master key

        user.output_cert(cert=cert.to_json(), ctype="admin")

    def gen_client_sig(self, client_id=b""):
        """the private key used here belongs to the server

        Returns:
            cert: Certificate
        """
        print("generate the client's certificate")
        user = self.user
        certif_file = user.admin_certificate_file
        server_cert = user.input_cert()
        server_cert = Certificate.from_json(server_cert)

        cert = Certificate()

        cert.payload.iss = user.id.decode()
        cert.payload.aud = client_id
        cert.payload.top_types = "non-top"
        cert.payload.admin_types = "local"

        exp = datetime.now()
        exp += timedelta(days=365)
        stamp = mktime(exp.timetuple())

        cert.payload.exp = format_date_time(stamp)
        cert.payload.mpk = user.input_mpk(mode="admin")
        cert.payload.parent.id = user.id
        cert.payload.parent.filename = "cert-" + user.id.decode() + ".conf"

        # calculate the hash of the server's cert
        cert.payload.parent.hash = sm3_hash(server_cert.to_bytes())

        cert.make_sig(user.input_sk(mode="admin"))

        return cert

    def gen_domain_sig(self, client_id=b"", client_mpk=b""):
        user = self.user
        server_cert = user.input_cert()
        server_cert = Certificate.from_json(server_cert)

        cert = Certificate()

        cert.payload.iss = user.id
        cert.payload.aud = client_id
        cert.payload.top_types = "non-top"
        cert.payload.admin_types = "admin"

        exp = datetime.now()
        exp += timedelta(days=365)
        stamp = mktime(exp.timetuple())

        cert.payload.exp = format_date_time(stamp)
        cert.payload.mpk = client_mpk
        cert.payload.parent.id = user.id
        cert.payload.parent.filename = "cert-" + user.id.decode() + ".conf"

        # calculate the hash of the server's cert
        cert.payload.parent.hash = sm3_hash(server_cert.to_bytes())

        cert.make_sig(user.input_sk(mode="admin"))

        return cert

    def run_run(self, action):
        if action.payload[0] == b"run_init":
            _, val = action.payload
            self.user.run_init(with_val=val, is_listening=True)

    def handle_thread(self, sock, addr, user=None):
        """the main function of handle thread

        Here we get byte stream from network, makes corresponding replies,
        sometimes maintains a "session"
        """

        # Some variables used in a thread but not users
        temp_vars = {
            "sm4key": b"",
            "mpk": b""
        }

        try:
            while True:
                data = sock.recv(RECEIVE_BUFFER_SIZE)
                if data:

                    # TODO(wrk): maybe generate some log information

                    # print("received: ", data)
                    print("data len: ", len(data))
                    action = self.gen_action_from_data(data, temp_vars=temp_vars)
                    if action:
                        if action.type == Action.ActionType.EXIT:
                            break
                        if action.type == Action.ActionType.ABORT:
                            # TODO(wrk): log some error infomation
                            break
                        if action.type == Action.ActionType.SEND:
                            assert(len(action.payload) == 1)
                            sock.send(action.payload[0])
                        if action.type == Action.ActionType.SEND_AND_EXIT:
                            assert(len(action.payload)==1)
                            sock.send(action.payload[0])
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
