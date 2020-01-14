#ifndef BYTE_HPP
#define BYTE_HPP

#include<crypto.h>

int sign_to_bytes(SignMesg *sig, char *buf);
SignMesg *sign_from_bytes(char *sig, int sig_len, int len);
char *key_to_bytes(IOTKey *key);
IOTKey *key_from_bytes(char *buf);

#endif