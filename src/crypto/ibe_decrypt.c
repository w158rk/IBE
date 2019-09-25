/**
 * @file ibe_decrypt.c
 * @author Wang Ruikai 
 * @date August 7th, 2019 
 * @brief ibe decrypt
 */

#include <crypto.h>

#include <openssl/sm9.h>
#include <openssl/bio.h>

int ibe_decrypt(const unsigned char* c_buf, size_t c_len, unsigned char* m_buff, size_t *m_len, 
    IBEPrivateKey *sk)
{
    SM9PrivateKey *sm9_sk = NULL;
    IBEPrivateKey buff = NULL;
    ibe_sk_copy(&buff, sk);

    #ifdef DEBUG 
    int i;
    for(i=0; i<IBE_SK_LEN; i++) {
        fprintf(stderr, "%02x ", (*sk)[i] & 0xff);
    }
    fprintf(stderr, "\n ");
    #endif
    d2i_SM9PrivateKey(&sm9_sk, &buff, IBE_SK_LEN);
    #ifdef DEBUG 
    for(i=0; i<IBE_SK_LEN; i++) {
        fprintf(stderr, "%02x ", (*sk)[i] & 0xff);
    }
    fprintf(stderr, "\n ");
    #endif

    #ifdef DEBUG 
    // i2d_SM9PrivateKey_fp(stderr, sm9_sk);
    fprintf(stderr, "\ntest3 : %ld\n", sm9_sk);
    #endif

    int ret = SM9_decrypt(NID_sm9encrypt_with_sm3_xor, c_buf, c_len, m_buff, m_len, sm9_sk);

    if(0 == ret) {
        ERROR("wrong in sm9 decryption (openssl)");
        goto end;
    }

    SM9PrivateKey_free(sm9_sk);
    return 1;

end:
    SM9PrivateKey_free(sm9_sk);
    return 0;

}
