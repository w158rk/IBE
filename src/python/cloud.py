
from constant import GLOBAL_DB
from packet import Packet
from utils import str2bytes, bytes2str
from base64 import urlsafe_b64encode, urlsafe_b64decode

import sqlite3


def upload(top_data=None, packet=None):
    user_id = None 
    mpk = None 
    sig = None

    if top_data:
        packet, sig = top_data

        # TODO(wrk): validate the signature 
         
        user_id = packet.vals[0]
        mpk = packet.vals[1] 

        user_id = bytes2str(user_id)
        mpk = urlsafe_b64encode(mpk)
        mpk = bytes2str(mpk)
        sig = urlsafe_b64encode(sig)
        sig = bytes2str(sig)

    elif packet:
        # currently we only tackle with the DOMAIN_SUBMIT packet 
        # first, we extract all the information out
        origin_packet = packet.vals[0]
        origin_packet = Packet.from_bytes(origin_packet)
        origin_sig = origin_packet.vals[1]
        origin_packet = origin_packet.vals[0]
        origin_packet = Packet.from_bytes(origin_packet)

        user_id = origin_packet.vals[0]
        mpk = origin_packet.vals[1]
        parent_sig = packet.vals[1]

        # the usable variables: origin_sig, parent_sig, user_id, mpk
        # TODO(wrk): validate the two signature

        # insert the information, all the things converted into str
        user_id = bytes2str(user_id)
        mpk = urlsafe_b64encode(mpk)
        mpk = bytes2str(mpk)
        sig = urlsafe_b64encode(parent_sig)
        sig = bytes2str(sig)

    db = sqlite3.connect(GLOBAL_DB)
    db.execute('''CREATE TABLE IF NOT EXISTS t_mpk
                (id         VARCHAR(32)    PRIMARY KEY              ,
                user_id     VARCHAR(32)                     NOT NULL,
                mpk         CHAR(512)                       NOT NULL,
                sig         CHAR(128)                        NOT NULL);
                ''')
    print("insert an entry to the database")
    db.execute("INSERT INTO t_mpk (user_id,mpk,sig) VALUES ('{}','{}','{}')".format(user_id, mpk, sig))
    db.commit()
    db.close()

def query_mpk(user_id):
    """
    get mpk from user_id
    """
    db = sqlite3.connect(GLOBAL_DB)
    db.execute("SELECT mpk, sig FROM t_mpk WHERE id={}".format(user_id))