/**
 * @file ibe_decrypt.c
 * @author Wang Ruikai 
 * @date August 7th, 2019 
 * @brief ibe decrypt
 */

#include <crypto.h>

#include <openssl/sm9.h>
#include <openssl/bio.h>

int ibe_decrypt(const char* c_buf, size_t c_len, char* m_buff, size_t *m_len, 
    IBEPrivateKey *sk, long sk_len)
{
    SM9PrivateKey *sm9_sk = NULL;
    IBEPrivateKey buff = NULL;
    ibe_sk_copy(&buff, sk, sk_len);

    d2i_SM9PrivateKey(&sm9_sk, &buff, sk_len);

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
