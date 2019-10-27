/**
 * @file sys_lib.c 
 * @brief functions about input and output parameters
 * @author Wang Ruikai 
 * @date August 7th, 2019
 */

// #define DEBUG

#ifdef DEBUG 
#include <stdio.h>
#endif

#include <openssl/bio.h>
#include <openssl/sm9.h>
#include <sys.h>

int get_mpk_fp(const char* mpk_filename, IBEPublicParameters* mpk) {

    SM9PublicParameters *sm9_mpk = NULL;

    FILE *mpk_fp = fopen(mpk_filename, "rb");
    if (!d2i_SM9PublicParameters_fp(mpk_fp, &sm9_mpk)){
		ERR_print_errors_fp(stderr);
        goto end;
    }
    
    fclose(mpk_fp);
    
    int rtn = i2d_SM9PublicParameters(sm9_mpk, mpk);

    #ifdef DEBUG 
    fprintf(stderr, "length of the public parameters : %d\n", rtn);
    #endif
    if(!rtn) {
        ERROR("i2d public parameters fails (openssl)");
        goto end;
    }
    
    SM9PublicParameters_free(sm9_mpk);
    return 1;

end: 
    fclose(mpk_fp);
    SM9PublicParameters_free(sm9_mpk);
    return 0;
}

int get_msk_fp(const char* msk_filename, IBEMasterSecret* msk) {

    int ret = 0;
    FILE *msk_fp = fopen(msk_filename, "rb");
    SM9MasterSecret *sm9_msk = NULL;

    #ifdef DEBUG 
    fprintf(stderr, "*msk_filename : %s\n", msk_filename);
    fprintf(stderr, "*msk : %ld\n", *msk);
    #endif

    if (!d2i_SM9MasterSecret_fp(msk_fp, &sm9_msk)) {
		ERR_print_errors_fp(stderr);
        goto end;
    }

    fclose(msk_fp);

    #ifdef DEBUG 
    fprintf(stderr, "*msk : %ld\n", *msk);
    #endif
    int rtn = i2d_SM9MasterSecret(sm9_msk, msk);
    #ifdef DEBUG 
    fprintf(stderr, "length of master secret : %d\n", rtn);
    fprintf(stderr, "*msk : %ld\n", *msk);
    #endif

    if(!rtn) {
        ERROR("i2d master secret fails (openssl)");
        goto end;
    }

    ret = 1;

end:
    fclose(msk_fp);
    SM9MasterSecret_free(sm9_msk);
    return ret;
}

int put_sk_fp(const char* sk_filename, IBEPrivateKey* sk) {
    
    SM9PrivateKey *sm9_sk = NULL;
    #ifdef DEBUG 
    int i;
    for (i=0; i<IBE_SK_LEN; i++){

        fprintf(stderr, "%02x ", (*sk)[i] & 0xff);
    }
    #endif
    if(!d2i_SM9PrivateKey(&sm9_sk, sk, IBE_SK_LEN)) {
        ERROR("convert from bytes to private key fails");
        goto end;
    }

    FILE *sk_fp = fopen(sk_filename, "wb");
    
    if (!i2d_SM9PrivateKey_fp(sk_fp, sm9_sk)) {
		ERR_print_errors_fp(stderr);
        goto end;
    }

    fclose(sk_fp);
    SM9PrivateKey_free(sm9_sk);

    return 1;

end:
    fclose(sk_fp);
    SM9PrivateKey_free(sm9_sk);
    return 0;    
}

int get_sk_fp(const char* sk_filename, IBEPrivateKey* sk) {
    SM9PrivateKey *sm9_sk = NULL;
    #ifdef DEBUG 
    printf("%s\n", sk_filename);
    #endif
    FILE *sk_fp = fopen(sk_filename, "rb");
    if (!d2i_SM9PrivateKey_fp(sk_fp, &sm9_sk)) {
		ERR_print_errors_fp(stderr);
        goto end;
    }

    #ifdef DEBUG 
    // i2d_SM9PrivateKey_fp(stderr, sm9_sk);
    #endif

    i2d_SM9PrivateKey(sm9_sk, sk);
    #ifdef DEBUG 
    fprintf(stderr, "test bug\n");
    #endif

    return 1;

end:
    fclose(sk_fp);
    return 0;
}
