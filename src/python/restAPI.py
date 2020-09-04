
import uvicorn
import argparse
import fastapi

from user import User
from base64 import urlsafe_b64encode
from utils import bytes2str
from client import Client
from crypto_c_interface import ibe_decrypt, ibe_read_from_file

_config_file = ""
_user = None
_client = None
_args = None
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


def main():
    set_env()
    if _user and _user.http_addr and _user.http_port:
        uvicorn.run("restAPI:app", host=_user.http_addr, port=_user.http_port, log_level="info")


if __name__ == "__main__":
    main()


@app.get("/")
def root():
    return "Rest API for a Node"


@app.get("/sk/request")
def request_for_sk():
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
    ret = _user.input_sk(mode="local")

    return urlsafe_b64encode(ret)


@app.get("/sec/request/addr/{addr}/port/{port}/user_id/{user_id}")
def request_for_sec(addr: str, port: int, user_id: str):
    if not _args:
        set_env()
    _args.action = "sec"
    _args.comm_addr = addr
    _args.comm_port = port
    _args.comm_id = user_id
    try:
        _client.run(args=_args)
    except Exception:
        return None

    with open("cipher.conf", "rb") as f:
        ret = f.read()

    return urlsafe_b64encode(ret)


@app.get("/dec/request")
def request_for_dec():
    # if not _args:
    #     set_env()
    # _args.action = "dec"
    # try:
    #     _client.run(args=_args)
    # except Exception:
    #     return None

    # with open("message.conf", "rb") as f:
    #     ret = f.read()

    # return ret.decode()
    with open("cipher.conf", "rb") as f:
        cipher = f.read()
    sk = ibe_read_from_file("sk-local.conf")
    ret = ibe_decrypt(cipher, sk)

    return ret


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

    item = {"sk": urlsafe_b64encode(sk), "mpk": urlsafe_b64encode(mpk), "msk": urlsafe_b64encode(msk), "cert": cert}

    return item
