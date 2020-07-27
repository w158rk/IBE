
def str2bytes(s):
    return bytes(s, encoding="utf-8")

def bytes2str(s):
    return str(s, encoding="utf-8")

def int2bytes(num, length):
    assert type(num) == int
    return num.to_bytes(length, 'little')

def bytes2int(bstr):
    return int.from_bytes(bstr, 'little')

