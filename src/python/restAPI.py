
import uvicorn
import argparse
import fastapi

from user import User
from base64 import urlsafe_b64encode
from utils import bytes2str
from client import Client
from crypto_c_interface import ibe_encrypt, ibe_decrypt, ibe_read_from_file, ibe_write_to_file, ibe_extract, ibe_setup, sm3_hash
from pydantic import BaseModel
from auth import Certificate
from datetime import datetime, timedelta
from time import mktime
from wsgiref.handlers import format_date_time

_config_file = ""
_user = None
_client = None
_args = None


class API_input(BaseModel):
    user_id: str = None
    user_mpk: bytes = None
    user_msk: bytes = None
    user_sk: bytes = None
    message: str = None
    cipher: bytes = None


app = fastapi.FastAPI()


def set_env():
    parser = argparse.ArgumentParser(description="IBE restAPI, currenly we recommend to user -c to provide a configuration file")
    parser.add_argument("--server-ip", action="store", dest="srv_addr",
                        type=str, default="localhost")
    parser.add_argument("--server-port", action="store", dest="srv_port",
                        type=int, default=10010)
    parser.add_argument('-c', type=str, nargs="?", default="",
                        dest="config_file", help='configuration file')
    parser.add_argument('--addr', type=str, default="", dest="comm_addr")
    parser.add_argument('--port', type=int, default=0, dest="comm_port")
    parser.add_argument('--id', type=str, default="", dest="comm_id")
    parser.add_argument('--key', type=str, default="sm4", dest="key_mode")

    global _args
    global _config_file
    global _user
    global _client

    _args = parser.parse_args()
    _config_file = _args.config_file

    if _config_file:
        _user = User(config_file=_config_file)
        _client = Client(_user)


# def main():
#     uvicorn.run(app=app, host='127.0.0.1', port=8000)
#     # set_env()
#     # if _user and _user.http_addr and _user.http_port:
#     #     uvicorn.run("restAPI:app", host=_user.http_addr, port=_user.http_port, log_level="info")


# if __name__ == "__main__":
#     main()


@app.get("/")
def root():
    return "Rest API for a Node"


@app.post("/sk")
def request_for_sk(item: API_input):

    assert item.user_id
    assert item.user_msk

    ret = ibe_extract(item.msk, item.user_id)

    return ret


@app.post("/sec/request")
def request_for_sec(item: API_input):

    assert item.message
    assert item.user_mpk
    assert item.user_id

    ret = ibe_encrypt(item.message, item.user_mpk, item.user_id)

    return ret


@app.post("/dec/request")
def request_for_dec(item: API_input):

    assert item.cipher
    assert item.user_sk

    ret = ibe_decrypt(item.cipher, item.user_sk)

    return ret


@app.post("/gen-domain/request")
def request_gen_domain(item: API_input):

    assert item.user_id

    ibe_setup("mpk.conf", "msk.conf", "mpk-len.conf", "msk-len.conf")

    mpk = ibe_read_from_file("mpk.conf")
    msk = ibe_read_from_file("mpk.conf")

    sk = ibe_extract(msk, item.user_id)
    ibe_write_to_file(sk, "sk.conf")

    out_item = {"msk": urlsafe_b64encode(msk), "mpk": urlsafe_b64encode(mpk), "sk": urlsafe_b64encode(sk)}

    return out_item


@app.get("/sk/request")
def request_for_comm_sk():
    # generate an args
    if not _args:
        set_env()
    _args.action = "sk"
    try:
        _client.run(args=_args)
    except Exception:
        return None
    # the private key would be output to the user's
    # local_sk_file, read and return that
    sk = _user.input_sk(mode="local")

    with open(_user.local_certificate_file, "rb") as f:
        cert = f.read()

    out_item = {"sk": urlsafe_b64encode(sk), "cert": cert}

    return out_item


@app.get("/domain/request")
def request_for_domain():
    if not _args:
        set_env()
    _args.action = "gen-domain"
    try:
        _client.run(args=_args)
    except Exception:
        return None

    sk = _user.input_sk(mode="admin")
    mpk = _user.input_mpk(mode="admin")
    msk = _user.input_msk()

    with open(_user.admin_certificate_file, "rb") as f:
        cert = f.read()

    out_item = {"msk": urlsafe_b64encode(msk), "mpk": urlsafe_b64encode(mpk), "sk": urlsafe_b64encode(sk), "cert": cert}

    return out_item


if __name__ == '__main__':
    uvicorn.run(app=app, host='127.0.0.1', port=8000)


# @app.get("/comm/sec/request/addr/{addr}/port/{port}/user_id/{user_id}")
# def request_for_comm_sec(addr: str, port: int, user_id: str):
#     if not _args:
#         set_env()
#     _args.action = "sec"
#     _args.comm_addr = addr
#     _args.comm_port = port
#     _args.comm_id = user_id
#     try:
#         _client.run(args=_args)
#     except Exception:
#         return None

#     with open("cipher.conf", "rb") as f:
#         ret = f.read()

#     return urlsafe_b64encode(ret)


# # @app.get("/sec/request")
# # def request_for_sec():
    

# @app.get("/dec/request")
# def request_for_dec():
#     with open("cipher.conf", "rb") as f:
#         cipher = f.read()
#     sk = ibe_read_from_file("sk-local.conf")
#     ret = ibe_decrypt(cipher, sk)

#     return ret

