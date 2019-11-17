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

#include "smx_lcl.h"
#include <openssl/bio.h>

int ibe_encrypt(const  char* data, size_t data_len,  char* c_buf, size_t *c_len, 
    IBEPublicParameters *mpk, long mpk_len, const char *id, size_t id_len) 
{
    SMXPublicParameters *sm9_mpk = NULL;
    if (!d2i_SMXPublicParameters(&sm9_mpk, mpk ,mpk_len)) {
        ERROR("cannot extract the public parameters");
        goto end;
    }

    int ret = SMX_encrypt(NID_sm9encrypt_with_sm3_xor, data, data_len,
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

int ibe_decrypt(const char* c_buf, size_t c_len, char* m_buff, size_t *m_len, 
    IBEPrivateKey *sk, long sk_len)
{
    SMXPrivateKey *sm9_sk = NULL;
    IBEPrivateKey buff = NULL;
    ibe_sk_copy(&buff, sk, sk_len);

    if(!d2i_SMXPrivateKey(&sm9_sk, &buff, sk_len))
    {
        ERROR("cannot parse sm9 sk");
        goto end;
    }

    int ret = SMX_decrypt(NID_sm9encrypt_with_sm3_xor, c_buf, c_len, m_buff, m_len, sm9_sk);

    if(0 == ret) {
        ERROR("wrong in sm9 decryption (openssl)");
        goto end;
    }

    SMXPrivateKey_free(sm9_sk);
    return 1;

end:
    SMXPrivateKey_free(sm9_sk);
    return 0;

}
