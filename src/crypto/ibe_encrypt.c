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
#include<string.h>

#include "smx_lcl.h"
#include "ibe_lcl.h"
#include "ibe_err.h"
#include <openssl/bio.h>

int ibe_encrypt(const  char* data, size_t data_len,  char* c_buf, size_t *c_len, 
    IBEPublicParameters *mpk, long mpk_len, const char *id, size_t id_len) 
{

    char *mpk_str = ibe_malloc_char(MPK_LEN);
    char *to_be_freed = mpk_str;

    memcpy(mpk_str, *mpk, mpk_len);
    SMXPublicParameters *smx_mpk = NULL;

    if (!d2i_SMXPublicParameters(&smx_mpk, &mpk_str ,mpk_len)) {
        ERROR(MPK_FROM_STR_ERROR);
        goto end;
    }

    int ret = SMX_encrypt(NID_sm9encrypt_with_sm3_xor, data, data_len,
		c_buf, c_len, smx_mpk, id, id_len);

    if(!ret) {

        ERROR(OPENSSL_ENC_ERROR);
        goto end;
    
    }

    //fprintf(stderr, "已加密！\n");

    return 1;

end:
    free(to_be_freed);
    return 0;
}

int ibe_decrypt(const char* c_buf, size_t c_len, char* m_buff, size_t *m_len, 
    IBEPrivateKey *sk, long sk_len)
{
    int ret = 0;

    SMXPrivateKey *smx_sk = NULL;
    char *sk_str = (char *)malloc(sk_len+1);
    char *to_be_freed = sk_str;
    sk_str[sk_len] = 0;
    memcpy(sk_str, *sk, sk_len);
    
    if(!d2i_SMXPrivateKey(&smx_sk, &sk_str, sk_len))
    {
        ERROR_WITH_LONG(SK_FROM_STR_ERROR, sk_len);
        goto end;
    }

    ret = SMX_decrypt(NID_sm9encrypt_with_sm3_xor, c_buf, c_len, m_buff, m_len, smx_sk);

    if(0 == ret) {
        ERROR(OPENSSL_DEC_ERROR);
        goto end;
    }

    ret = 1;

end:

    free(to_be_freed);   
    if(smx_sk)
        SMXPrivateKey_free(smx_sk);
    return ret;

}
