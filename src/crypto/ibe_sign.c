#include <crypto.h>

#include "smx_lcl.h"
#include "ibe_lcl.h"
#include "ibe_err.h"

#include <string.h>
//#include "sm9_lcl.h"

int ibe_sign(const char* data, size_t data_len,  char* sign_buf, size_t *sign_len, 
    IBEPrivateKey *sk, long sk_len)
{
    // if(sk_len != SK_LEN&&sk_len != SK_LEN-1)
    // {
    //     ERROR_WITH_LONG(SK_LEN_ERROR, sk_len);
    //     return 0;
    // }

    int ret = 0;
    SMXPrivateKey *smx_sk = NULL;
    char *buf = ibe_malloc_char(sk_len);
    char *to_be_free = buf;

    memcpy(buf, *sk, sk_len);

    if(!d2i_SMXPrivateKey(&smx_sk, &buf, sk_len))
    {
        ERROR(SK_FROM_STR_ERROR);
        goto end;
    }

    if(!SMX_sign(NID_sm3, data, data_len, sign_buf, sign_len, smx_sk))
    {
        ERROR(OPENSSL_SIGN_ERROR);
        goto end;
    }

    ret = 1;

end:
    ibe_free_char(to_be_free);
    return ret;
}

int ibe_verify(const  char* data, size_t data_len,  char* sign_buf, size_t sign_len, 
    IBEPublicParameters *mpk, long mpk_len, const char *id, size_t id_len)
{

    int ret = 0;
    SMXPublicParameters *smx_mpk = NULL;
    char *buf = ibe_malloc_char(MPK_LEN);
    char *to_be_free = buf;

    memcpy(buf, *mpk, MPK_LEN);

    if(!d2i_SMXPublicParameters(&smx_mpk, &buf, MPK_LEN))
    {
        ERROR(MPK_FROM_STR_ERROR);
        goto end;
    }

    if(!SMX_verify(NID_sm3, data, data_len, sign_buf, sign_len, smx_mpk, id, id_len))
    {
        ERROR(OPENSSL_VERIFY_ERROR);
        goto end;
    }

    ret = 1;

end:
    ibe_free_char(to_be_free);
    return ret;
}

