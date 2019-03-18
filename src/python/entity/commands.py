from enums import *

class SecurityCommand:
    
    def __init__(self):
        self.cryptoCommand = None
        self.signCommand = None
        self.certifyCommand = None
        # self.encryptCommand = None

class CryptoCommand:

    def __init__(self):
        self.type = None 
        self.key = None 

    def setIBE(self):
        self.type = CryptoType.IBE

class SignCommand:
    def __init__(self):
        self.type = None 
        self.key = None 

class CertifyCommand:
    def __init__(self):
        self.type = None 
        self.key = None