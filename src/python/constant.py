BUFFER_SIZE = 1024
RECEIVE_BUFFER_SIZE = 8192
BN_BIT_SIZE = 256
BN_HEX_SIZE = BN_BIT_SIZE//4 + 1
BN_BYTE_SIZE = BN_BIT_SIZE//8

"variables for c_interface"
# ROOT_DIR = "/home/wrk/workspace/ustc-m/IBE"
ROOT_DIR = "/home/wxy/work/IBE"
ARTIFACT_DIR = ROOT_DIR + "/build"
LIBRARY_DIR = ARTIFACT_DIR + "/lib"
LIBIBE_PATH = LIBRARY_DIR + "/libibe.so"

EC_POINT_LEN = 66
POINT_LEN = 129
