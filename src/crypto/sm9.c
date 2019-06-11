#include <stdio.h>
#include <string.h>
#include <stdlib.h>

# include <openssl/evp.h>
# include <openssl/err.h>
# include <openssl/sm9.h>
# include <openssl/rand.h>

int system_setup(const char* mpk_filename, const char* msk_filename) {
   	SM9PublicParameters *mpk = NULL;
	SM9MasterSecret *msk = NULL;

   	if (!SM9_setup(NID_sm9bn256v1, NID_sm9encrypt, NID_sm9hash1_with_sm3, &mpk, &msk)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

    FILE *mpk_fp = fopen(mpk_filename, "wb");
    if (!i2d_SM9PublicParameters_fp(mpk_fp, mpk)){
		ERR_print_errors_fp(stderr);
        fclose(mpk_fp);
        goto end;
    }
    fclose(mpk_fp);

    FILE *msk_fp = fopen(msk_filename, "wb");
    if (!i2d_SM9MasterSecret_fp(msk_fp, msk)) {
		ERR_print_errors_fp(stderr);
        fclose(msk_fp);
        goto end;
    }
    fclose(msk_fp);
    return 0;

end:
	SM9PublicParameters_free(mpk);
	SM9MasterSecret_free(msk);
    return -1;

}

int get_mpk_fp(const char* mpk_filename, SM9PublicParameters* mpk) {
    // 从文件中获取加密参数 

    FILE *mpk_fp = fopen(mpk_filename, "rb");
    if (!d2i_SM9PublicParameters_fp(mpk_fp, &mpk)){
		ERR_print_errors_fp(stderr);
        goto end;
    }
    
    fclose(mpk_fp);
    return 0;

end: 
    fclose(mpk_fp);
    return -1;
}

int get_msk_fp(const char* msk_filename, SM9MasterSecret* msk) {
    // 从文件中获取主密钥 

    FILE *msk_fp = fopen(msk_filename, "rb");
    if (!d2i_SM9MasterSecret_fp(msk_fp, &msk)) {
		ERR_print_errors_fp(stderr);
        goto end;
    }

    fclose(msk_fp);
    return 0;

end:
    fclose(msk_fp);
    return -1;
}

/*
 * private key 
 *      extract 
 *      get from files
 *      put from files
 */

SM9PrivateKey* extract_private_key(SM9MasterSecret* msk, const char* id) {
    return SM9_extract_private_key(msk, id, strlen(id));
}

int put_sk_fp(const char* sk_filename, SM9PrivateKey* sk) {
    FILE *sk_fp = fopen(sk_filename, "wb");
    if (!i2d_SM9PrivateKey_fp(sk_fp, sk)) {
		ERR_print_errors_fp(stderr);
        goto end;
    }

    fclose(sk_fp);
    return 0;

end:
    fclose(sk_fp);
    return -1;    
}

int get_sk_fp(const char* sk_filename, SM9PrivateKey* sk) {
    FILE *sk_fp = fopen(sk_filename, "rb");
    if (!d2i_SM9PrivateKey_fp(sk_fp, &sk)) {
		ERR_print_errors_fp(stderr);
        goto end;
    }

    fclose(sk_fp);
    return 0;

end:
    fclose(sk_fp);
    return -1;
}

/* 
 * encrypt 
 */

int sm9_encrypt(const unsigned char* data, size_t data_len, unsigned char* c_buf, size_t *c_len, 
    SM9PublicParameters *mpk, const char *id, size_t id_len) {
    int ret = SM9_encrypt(NID_sm9encrypt_with_sm3_xor, data, data_len,
		c_buf, c_len, mpk, id, strlen(id));
    if(!ret) 
        return -1; 
    return ret;
}

int sm9_decrypt(const unsigned char* c_buf, size_t c_len, unsigned char* m_buff, size_t *m_len, 
    SM9PrivateKey *sk) {
    int ret = SM9_decrypt(NID_sm9encrypt_with_sm3_xor, c_buf, c_len, m_buff, m_len, sk);
    if(!ret) {
		ERR_print_errors_fp(stderr);
        return -1; 
    }
    return ret;
}

