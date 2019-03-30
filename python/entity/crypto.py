# from commands import CryptoCommand
import subprocess

appdir = "./build/app/"

def setup():
    status = subprocess.call("./build/app/setup", shell=True)

def extract(id):
    status = subprocess.call(appdir+"extract " + id, shell=True)

def encrypt(m, id):
    """
    take 64 bytes as an unit to encrypt, now only encrypt less than a unit has been implemented
    """
    status = subprocess.call("./build/app/encrypt " + id + " " + m, shell=True)

def decrypt(id):
    status = subprocess.call("./build/app/decrypt " + id, shell=True)


