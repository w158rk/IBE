/**
 * @file sys_lib.c 
 * @brief functions about input and output parameters
 * @author Wang Ruikai 
 * @date August 7th, 2019
 */

// 

#ifdef DEBUG 
#include <stdio.h>
#endif

#include <string.h>
#include <openssl/bio.h>
#include <openssl/smx.h>
#include <sys.h>

int get_mpk_fp(const char* mpk_filename, IBEPublicParameters* mpk) {

    SMXPublicParameters *smx_mpk = NULL;

    FILE *mpk_fp = fopen(mpk_filename, "rb");
    if (!d2i_SMXPublicParameters_fp(mpk_fp, &smx_mpk)){
		ERR_print_errors_fp(stderr);
        goto end;
    }
    
    
    int rtn = i2d_SMXPublicParameters(smx_mpk, mpk);

    if(!rtn) {
        ERROR("i2d public parameters fails (openssl)");
        goto end;
    }

    fclose(mpk_fp);
    
    SMXPublicParameters_free(smx_mpk);
    return 1;

end: 
    fclose(mpk_fp);
    SMXPublicParameters_free(smx_mpk);
    return 0;
}

int put_mpk_fp(const char* mpk_filename, IBEPublicParameters* mpk, long mpk_len) {
    int ret;
    
    char *mpk_str = (char *)malloc(mpk_len+1);
    mpk_str[mpk_len] = 0;
    memcpy(mpk_str, *mpk, mpk_len);

    SMXPublicParameters *smx_mpk = NULL;
    if(!d2i_SMXPublicParameters(&smx_mpk, &mpk_str, mpk_len))
    {
        ERROR("convert from bytes to mpk fails");
        goto end;
    }

    FILE *mpk_fp = fopen(mpk_filename, "wb");
    
    if (! i2d_SMXPrivateKey_fp(mpk_fp, smx_mpk)) {
        ERROR("cannot put sk to file");
        goto end;
    }

    ret = 1;

end:
    fclose(mpk_fp);
    return ret;    
}


int get_msk_fp(const char* msk_filename, IBEMasterSecret* msk) {

    int ret = 0;
    FILE *msk_fp = fopen(msk_filename, "rb");
    SMXMasterSecret *smx_msk = NULL;

    if (!d2i_SMXMasterSecret_fp(msk_fp, &smx_msk)) {
		ERR_print_errors_fp(stderr);
        goto end;
    }

    int rtn = i2d_SMXMasterSecret(smx_msk, msk);

    if(!rtn) {
        ERROR("i2d master secret fails (openssl)");
        goto end;
    }

    ret = 1;

end:
    fclose(msk_fp);
    SMXMasterSecret_free(smx_msk);
    return ret;
}

int put_sk_fp(const char* sk_filename, IBEPrivateKey* sk, long sk_len) {
    int ret;
    
    char *sk_str = (char *)malloc(sk_len+1);
    sk_str[sk_len] = 0;
    memcpy(sk_str, *sk, sk_len);

    SMXPrivateKey *smx_sk = NULL;
    if(!d2i_SMXPrivateKey(&smx_sk, &sk_str, sk_len)) {
        ERROR("convert from bytes to private key fails");
        return 0;
    }

    FILE *sk_fp = fopen(sk_filename, "wb");
    
    if (! i2d_SMXPrivateKey_fp(sk_fp, smx_sk)) {
        ERROR("cannot put sk to file");
        goto end;
    }


#ifdef DEBUG 
    // fseek(sk_fp, 0, SEEK_END);
    // long len = ftell(sk_fp);
    // fclose(sk_fp);
    // fprintf(stderr, "len of sk: %ld\n", len);
#endif

    ret = 1;

end:
    fclose(sk_fp);
    SMXPrivateKey_free(smx_sk);
    return ret;    
}

int get_sk_fp(const char* sk_filename, IBEPrivateKey* sk) {
    SMXPrivateKey *smx_sk = NULL;
    FILE *sk_fp = fopen(sk_filename, "rb");
    if (!d2i_SMXPrivateKey_fp(sk_fp, &smx_sk)) {
		ERROR("cannot get the sk from file");
        goto end;
    }

    long len = i2d_SMXPrivateKey(smx_sk, sk);
    if(!len)
    {
        ERROR("cannot convert sk to string");
        goto end;
    }
#ifdef DEBUG
    fprintf(stderr, "[sys_lib] len of sk: %ld\n", len);
#endif

    return 1;

end:
    fclose(sk_fp);
    return 0;
}
