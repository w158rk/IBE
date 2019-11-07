#include <crypto.h>

#include <openssl/sm9.h>

#include <string.h>
//#include "sm9_lcl.h"

int ibe_sign(const unsigned char *data, size_t data_length, const unsigned char* sign, size_t *sign_length, SM9PrivateKey *sk)
{
    int ret = -1;
	printf("Here");
	printf("data in sign is %s\n", data);
    printf("sk is sign is %s\n", sk);
    ret = SM9_sign(NID_sm3, data, data_length, sign, sign_length, sk);
    return ret;
}

int ibe_verify(const unsigned char* data, size_t data_length, const unsigned char *sign, size_t sign_length, SM9PublicParameters *mpk, const char *id, size_t id_length)
{
    int ret = -1;
    ret = SM9_verify(NID_sm3, data, data_length, sign, sign_length, mpk, id, id_length);
    return ret;
}

