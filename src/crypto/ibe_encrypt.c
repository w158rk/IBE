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

int ibe_encrypt(const unsigned char* data, size_t data_len, unsigned char* c_buf, size_t *c_len, 
    IBEPublicParameters *mpk, const char *id, size_t id_len) 
{
    SM9PublicParameters *sm9_mpk = NULL;
    if (!d2i_SM9PublicParameters(&sm9_mpk, mpk ,IBE_PP_LEN)) {
        ERROR("cannot extract the public parameters");
        goto end;
    }

    #ifdef DEBUG 
    fprintf(stderr, "\ntest2 : %ld\n", sm9_mpk);
    #endif

    int ret = SM9_encrypt(NID_sm9encrypt_with_sm3_xor, data, data_len,
		c_buf, c_len, sm9_mpk, id, id_len);

    #ifdef DEBUG 
    fprintf(stderr, "test2\n");
    #endif

    if(!ret) {

        ERROR("error in sm9 encrypt (openssl) ");
        goto end;
    
    }

    return 1;

end:
    return 0;
}
