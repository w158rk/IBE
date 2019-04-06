# from commands import CryptoCommand
from json import load
from random import choice
from sys import platform
from subprocess import call

cfgPath = 'python/entity/crypto.cfg'

with open(cfgPath, 'r') as f:
    params = load(f)
    f.close()
bindir = params['bindir'][platform]


def setup():
    status = call(bindir+"setup", shell=True)

def extract(id):
    status = call(bindir+"extract " + id, shell=True)

def encrypt(m, id):
    """
    IBE encrypt, return (u,v)
    """
    # generate the input files for the c program
    prefix = "ibe_"
    randstr = gen_random_str()
    typeList = [m, id]
    strList = ["m", "sk"]
    outputFiles(prefix, randstr, typeList, strList)

    # run the program
    index = "encrypt_ibe"
    command = bindir + params['commands'][index]
    args = params["args_format"][index].format(randstr, id) 
    _ = call(command + " " + args)

    # get the result
    strList = ["u", "v"]
    filename = prefix+"_m_"+randstr
    res = inputFiles(prefix, randstr, strList)

    # remove the temp files 
    command = params['commands']["clean"][platform]
    _ = call(command + " " + args )             

    return (res[0], res[1])         # return (u, v)

def decrypt(u, v, id):
    """
    decrypt, return piain text
    """
    # generate the input files for the c program
    prefix = "ibe_"
    randstr = gen_random_str()
    typeList = [u, v, id]
    strList = ["u", "v", "sk"]
    outputFiles(prefix, randstr, typeList, strList)
    
    # run the program
    index = "decrypt_ibe"
    command = bindir + params['commands'][index]
    args = params["args_format"][index].format(randstr, id) 
    _ = call(command + " " + args)

    # get the result
    res = inputFiles(prefix, randstr, ['m'])

    # remove the temp files 
    command = params['commands']["clean"][platform]
    _ = call(command + " " + args )             

    return res[0]

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
    prefix = "aes"

    # generate the input files for the c program
    randstr = gen_random_str()
    typeList = [text, key, iv]
    strList = ["in", "key", "iv"]
    outputFiles(prefix, randstr, typeList, strList)

    # run the encrypt program
    command = bindir + params['commands'][type+'_aes']
    args = params["args_format"]['aes'].format(randstr)  
    _ = call(command + " " + args )             

    # read the result 
    res = inputFiles(prefix, randstr, ['out'])
    
    # remove the temp files 
    command = params['commands']["clean"][platform]
    _ = call(command + " " + args )             

    return res[0]

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
        filename = prefix+s+randstr
        with open(filename,"rb") as f:
            temp = f.read()
            res.append(temp)
            f.close()
    return res

def outputFiles(prefix, randstr, typeList, strList):
    for m,s in zip(typeList, strList):
        filename = prefix + s + "_" + randstr
        with open(filename,"wb") as f:
            f.write(m)
            f.close()
        

class AESTypeError(TypeError):
    pass