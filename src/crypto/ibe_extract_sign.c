#ifdef DEBUG 
#include<stdio.h>
#endif

#include <crypto.h>

#include <openssl/sm9.h>
#include <openssl/bio.h>

int ibe_extract_sign(IBEPrivateKey *sk,
                long *sk_len,
                IBEMasterSecret* msk,
                long msk_len, 
                const char* id,
                size_t id_len,
                char *sign_data)
{
    int ret = 0;

    int sign_len;

    // char sign_data[10000] = {'\0'};
    // size_t sign_len = 0;
    SM9MasterSecret *sm9_ms = NULL;

    d2i_SM9MasterSecret(&sm9_ms, msk, msk_len);

    SM9PrivateKey *sm9_sk = SM9_extract_private_key(sm9_ms, id, id_len);

    fprintf(stderr, "sm9_sk: %ld\n", sm9_sk);

    int len = i2d_SM9PrivateKey(sm9_sk, sk);
    if (0 == len) {
        ERROR("extract the private key fail, please try it again");
        goto end;
    }
    *sk_len = (long)len;

    int ret2 = SM9_sign(NID_sha256, "Hello", 5, sign_data, &sign_len, sm9_sk);

    fprintf(stderr,"sign is: %ld", sign_data);

    fprintf(stderr, "sign_len: %ld\n", sign_len);

    fprintf(stderr, "ret: %ld\n", ret2);

    ret = sign_len;

    // IBEPublicParameters *mpk;
    // SM9PublicParameters *sm9_mpk = NULL;

    // FILE *mpk_fp = fopen("mpk.conf", "rb");
    // if (!d2i_SM9PublicParameters_fp(mpk_fp, &sm9_mpk)){
	// 	ERR_print_errors_fp(stderr);
    //     goto end;
    // }
    
    // fclose(mpk_fp);
    
    // int rtn = i2d_SM9PublicParameters(sm9_mpk, mpk);

    // if(!rtn) {
    //     ERROR("i2d public parameters fails (openssl)");
    //     goto end;
    // }

    // int ret3 = SM9_verify(NID_sm3, "Hello", 5, sign_data, sign_len, &mpk, "Server", 6);

    // fprintf(stderr, "ret3: %ld\n", ret3);

end : 
    SM9_MASTER_KEY_free(sm9_ms);
    SM9PrivateKey_free(sm9_sk);

    return ret;
}