# from command import CryptoCommand
from json import load
from random import choice, randint
from sys import platform
from subprocess import call

cfgPath = 'python/entity/crypto.cfg'

with open(cfgPath, 'r') as f:
    params = load(f)
    f.close()
bindir = params['bindir'][platform]

#########################################
##              IBE 
#########################################

def setup():
    index = "setup"
    command = bindir + params['command'][index]
    _ = call(command, shell=True)

def extract(uid):
    prefix = "ibe_"

    # run the program
    index = "extract"
    command = bindir + params['command'][index]
    args = params["args_format"][index].format(uid) 
    _ = call(command + " " + args, shell=True)

    # get the result
    strList = ["sk"]
    res = inputFiles(prefix, uid, strList)

    command = params['command']["clean"][platform]
    _ = call(command + " " + args, shell=True )             

    return res[0]            # return sk

def encrypt(m, id):
    """
    IBE encrypt, return (u,v)
    """
    # generate the input files for the c program
    prefix = "ibe_"
    randstr = gen_random_str()
    typeList = [m, id]
    print("[encrypt] ", m)
    print("[encrypt] ", id)
    strList = ["m", "id"]
    outputFiles(prefix, randstr, typeList, strList)

    # run the program
    index = "encrypt_ibe"
    command = bindir + params['command'][index]
    args = params["args_format"][index].format(randstr) 
    _ = call(command + " " + args, shell=True)
    print(command + " " + args)

    # get the result
    strList = ["u", "v"]
    res = inputFiles(prefix, randstr, strList)

    # remove the temp files 
    command = params['command']["clean"][platform]
    _ = call(command + " " + args, shell=True )             
    print(res[0])
    print(res[1])

    return (res[0], res[1])         # return (u, v)

def decrypt(u, v, sk):
    """
    decrypt, return piain text
    """
    # generate the input files for the c program
    prefix = "ibe_"
    randstr = gen_random_str()
    typeList = [u, v, sk]
    print(u)
    print(v)
    strList = ["u", "v", "sk"]
    outputFiles(prefix, randstr, typeList, strList)
    
    # run the program
    index = "decrypt_ibe"
    command = bindir + params['command'][index]
    args = params["args_format"][index].format(randstr) 
    _ = call(command + " " + args, shell=True)
    print(command + " " + args)

    # get the result
    res = inputFiles(prefix, randstr, ['m'])

    # remove the temp files 
    command = params['command']["clean"][platform]
    _ = call(command + " " + args, shell=True)             

    return str(res[0])

#############################################
##              aes
#############################################
def gen_key_aes():
    """
    generate a 256 bits(32 bytes) key
    """

    res = [randint(0, 255) for i in range(32)]
    return bytes(res)

def gen_iv_aes():
    """
    generate a 128 bits(32 bytes) key
    """

    res = [randint(0, 256) for i in range(16)]
    return bytes(res)


def encrypt_aes(m, key, iv):
    """
    m,key,iv are all string(I don't know if it works with byte string)
    length of 
        m : multiple of 16 bytes
        key : 32 bytes
        iv : 16 bytes
    """
    return aes("encrypt", m, key, iv)

def decrypt_aes(c, key, iv):
    return aes("decrypt", c, key, iv)

def aes(type, text, key, iv):
    if type not in ['encrypt', 'decrypt']:
        raise AESTypeError
    prefix = "aes_"

    # generate the input files for the c program
    randstr = gen_random_str()
    typeList = [text, key, iv]
    strList = ["in", "key", "iv"]
    outputFiles(prefix, randstr, typeList, strList)

    # run the encrypt program
    command = bindir + params['command'][type+'_aes']
    args = params["args_format"]['aes'].format(randstr)  
    _ = call(command + " " + args, shell=True)             

    # read the result 
    res = inputFiles(prefix, randstr, ['out'])
    
    # remove the temp files 
    command = params['command']["clean"][platform]
    _ = call(command + " " + args, shell=True)             

    return res[0]

#########################################################
##          utils
#########################################################

def gen_random_str():
    letters = "abcdefghijklmnopqrstuvwxyz"
    length = 2                  # randome string length
    randstr = ''.join(choice(letters) for _ in range(length))
    return randstr

def inputFiles(prefix, randstr, strList):
    if not strList:
        raise RuntimeError("No files to put in")
    res = []
    for s in strList:
        filename = prefix + s + "_"  +randstr
        with open(filename,"rb") as f:
            temp = f.read()
            res.append(temp)
            f.close()
    return res

def outputFiles(prefix, randstr, typeList, strList):
    for m,s in zip(typeList, strList):
        filename = prefix + s + "_" + randstr
        if isinstance(m, str):
            m = bytes(m, encoding="utf8")
        with open(filename,"wb") as f:
            f.write(m)
            f.close()
        

class AESTypeError(TypeError):
    pass