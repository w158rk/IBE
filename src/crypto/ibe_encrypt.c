/**
 * @file ibe_encrypt.c
 * @author Wang Ruikai 
 * @date August 7th, 2019
 * @brief ibe encrypt
 */

#ifdef DEBUG 
#include <stdio.h>
#endif

#include<crypto.h>

#include <openssl/sm9.h>
#include <openssl/bio.h>

int ibe_encrypt(const  char* data, size_t data_len,  char* c_buf, size_t *c_len, 
    IBEPublicParameters *mpk, long mpk_len, const char *id, size_t id_len) 
{
    SM9PublicParameters *sm9_mpk = NULL;
    if (!d2i_SM9PublicParameters(&sm9_mpk, mpk ,mpk_len)) {
        ERROR("cannot extract the public parameters");
        goto end;
    }

    int ret = SM9_encrypt(NID_sm9encrypt_with_sm3_xor, data, data_len,
		c_buf, c_len, sm9_mpk, id, id_len);

    if(!ret) {

        ERROR("error in sm9 encrypt (openssl) ");
        goto end;
    
    }

    //fprintf(stderr, "已加密！\n");

    return 1;

end:
    return 0;
}
