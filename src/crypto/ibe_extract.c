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

#include "smx_lcl.h"
#include "ibe_err.h"
#include <openssl/bio.h>

int ibe_extract(IBEPrivateKey *sk,
                long *sk_len,
                IBEMasterSecret* msk,
                long msk_len, 
                const char* id,
                size_t id_len)
{
    int ret = 0;
    SMXMasterSecret *sm9_ms = NULL;

    d2i_SMXMasterSecret(&sm9_ms, msk, msk_len);

    SMXPrivateKey *sm9_sk = SMX_extract_private_key(sm9_ms, id, id_len);

    int len = i2d_SMXPrivateKey(sm9_sk, sk);
    if (0 == len) {
        ERROR(SK_FROM_STR_ERROR);
        goto end;
    }
    *sk_len = (long)len;

    ret = 1;

end : 
    SMX_MASTER_KEY_free(sm9_ms);
    SMXPrivateKey_free(sm9_sk);

    return ret;
}