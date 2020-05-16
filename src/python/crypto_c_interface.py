"""
module: 
"""


from ctypes import *

root_dir = "../.."
artifact_dir = root_dir + "/build-r"
library_dir = artifact_dir + "/lib"

libibe_path = library_dir + "/libibe.so"
mylib = CDLL(libibe_path)
