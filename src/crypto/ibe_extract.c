/**
 * @file ibe_extract.c
 * @author Wang Ruikai 
 * @date August 7th, 2019 
 * @brief ibe extract private key
 */

// #define DEBUG
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

    #ifdef DEBUG 
    fprintf(stderr, "&msk : %ld \n", msk);
    int i;
    for(i=0; i<128; i++) {
        fprintf(stderr, "%02x ", (*msk)[i] & 0xff);
    }
    fprintf(stderr, "\n ");

    fprintf(stderr, "id : %s \n", id);
    #endif

    d2i_SM9MasterSecret(&sm9_ms, msk, IBE_MS_LEN);

    #ifdef DEBUG 
    fprintf(stderr, "id length : %d\n", id_len);
    #endif

    SM9PrivateKey *sm9_sk = SM9_extract_private_key(sm9_ms, id, id_len);
    #ifdef DEBUG 
    fprintf(stderr, "id : %s\n", id);
    #endif


    int flg = i2d_SM9PrivateKey(sm9_sk, sk);
    if (0 == flg) {
        ERROR("extract the private key fail, please try it again");
        goto end;
    }

    #ifdef DEBUG 
    fprintf(stderr, "\nlength of sk : %d\n", flg);
    #endif

    #ifdef DEBUG 
    for(i=0; i<IBE_SK_LEN; i++) {
        fprintf(stderr, "%02x ", (*sk)[i] & 0xff);
    }
    fprintf(stderr, "\n ");
    #endif

    ret = 1;

end : 
    SM9_MASTER_KEY_free(sm9_ms);
    SM9PrivateKey_free(sm9_sk);

    return ret;
}