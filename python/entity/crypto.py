# from commands import CryptoCommand
from sys import platform
from subprocess import call

bindirs ={
    "unix" : "./build/bin/",
    "win32" : ".\\build\\bin\\"
} 

bindir = bindirs[platform]

def setup():
    status = call(bindir+"setup", shell=True)

def extract(id):
    status = call(bindir+"extract " + id, shell=True)

def encrypt(m, id):
    """
    take 64 bytes as an unit to encrypt, 
    now only encrypt less than a unit has been implemented
    """
    print(platform)
    print("encrypt")
    status = call(bindir+"encrypt " + id + " " + m, shell=True)
    print("encrypt finished")

def decrypt(id):
    status = call(bindir+"decrypt " + id, shell=True)


