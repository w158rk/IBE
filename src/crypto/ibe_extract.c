/**
 * @file ibe_extract.c
 * @author Wang Ruikai 
 * @date August 7th, 2019 
 * @brief ibe extract private key
 */

// 
#ifdef DEBUG 
#include<stdio.h>
#endif

#include <crypto.h>

#include <openssl/sm9.h>
#include <openssl/bio.h>

int ibe_extract(IBEPrivateKey *sk, 
                IBEMasterSecret* msk, 
                const char* id,
                size_t id_len)
{
    int ret = 0;
    SM9MasterSecret *sm9_ms = NULL;

    d2i_SM9MasterSecret(&sm9_ms, msk, IBE_MS_LEN);

    SM9PrivateKey *sm9_sk = SM9_extract_private_key(sm9_ms, id, id_len);

    int flg = i2d_SM9PrivateKey(sm9_sk, sk);
    if (0 == flg) {
        ERROR("extract the private key fail, please try it again");
        goto end;
    }

    ret = 1;

end : 
    SM9_MASTER_KEY_free(sm9_ms);
    SM9PrivateKey_free(sm9_sk);

    return ret;
}