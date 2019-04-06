from subprocess import Popen, call 
from sys import platform

bindirs ={
    "linux" : "./python/",
    "win32" : ".\\python\\"
} 
bindir  = bindirs[platform]

Popen("python " + bindir+"server.py", shell=True)           # run a server in the background
call("python " + bindir+"client.py", shell=True)