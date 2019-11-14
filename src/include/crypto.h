/** 
 * @file crypto.h 
 * @author Wang Ruikai 
 * @date July 13th, 2019 
 * @brief File contains the definitions and declarations of the cryptography 
 *              stuffs 
 *      */


#ifndef CRYPTO_H
#define CRYPTO_H 

#ifdef __cplusplus
extern "C" {
#endif

#include "utils.h"
#include "ds.h"

#include <openssl/sm4.h>
#include <openssl/sm9.h>

/* key lengths */
#define AES_KEY_BITS            256 
#define AES_KEY_LEN             (AES_KEY_BITS/8)
#define AES_IV_BITS             128
#define AES_IV_LEN              (AES_IV_BITS/8)
#define SM4_KEY_BITS            128
#define SM4_KEY_LEN             (SM4_KEY_BITS/8)




/**
 * @brief map an ID to point 
 * @return 1 if no errors , else 0
 * @param[out] point the initial value of point should be the address of a NULL point
 * @param[in] id ID
 * @param[in] id_len length of ID
 * @param[in] mpk_file the filename of the file where the mpk is stored, should end with '\0
 */
int ibe_id2point_init(
    EC_POINT **point,    
    char *id, 
    long id_len,
    char *mpk_file
); 


int ibe_setup(
    char *mpk_file,
    char *msk_file,
    char *mpk_len_file,
    char *msk_len_file
);

int ibe_setup_sign(
    char *mpk_file,
    char *msk_file,
    char *mpk_len_file,
    char *msk_len_file
);
int ibe_encrypt(const  char* data, size_t data_len,  char* c_buf, size_t *c_len, 
    IBEPublicParameters *mpk, long mpk_len, const char *id, size_t id_len);
int ibe_decrypt(const  char* c_buf, size_t c_len,  char* m_buff, size_t *m_len, 
    IBEPrivateKey *sk, long sk_len);

/**
 * @brief extract ibe private key 
 * @return 1 if no errors , else 0
 * @param[out] sk private key 
 * @param[in] msk Master Secret
 * @param[in] id the ID of the request launcher
 * @param[in] id_len length of id
 */
int ibe_extract(IBEPrivateKey *sk, 
                long *,
                IBEMasterSecret* msk, 
                long msk_len,
                const char* id,
                size_t id_len);

int ibe_extract_sign(IBEPrivateKey *sk,
                        long *sk_len,
                        IBEMasterSecret* msk,
                        long msk_len, 
                        const char* id,
                        size_t id_len,
                        char *sign_data);


void ibe_sk_copy(IBEPrivateKey *dest, IBEPrivateKey *src, long);
int ibe_sign(const unsigned char *data, size_t data_length, const unsigned char* sign, size_t *sign_length, SM9PrivateKey *sk);
int ibe_verify(const unsigned char* data, size_t data_length, const unsigned char *sign, size_t sign_length, SM9PublicParameters *mpk, const char *id, size_t id_length);

/*
 * cbc 
 */



int put_iv_fp(const char* filename, const char* iv, size_t len);
int get_iv_fp(const char* filename, char* iv, size_t len);
int gen_random_iv(char *iv);
int gen_random_key(char *key);

void gen_random_sm4(unsigned char *key);
void set_key(unsigned char *key, FILE* filename);
void get_key(unsigned char *key, FILE* filename);
void sm4_setkey_enc( sm4_context *ctx, unsigned char key[16] );
void sm4_setkey_dec( sm4_context *ctx, unsigned char key[16] );
void sm4_crypt_ecb( sm4_context *ctx,
				     int mode,
					 int length,
                     unsigned char *input,
                     unsigned char *output,
                     int *output_lenth);
#ifdef __cplusplus
}
#endif
#endif 

