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


#include <ibe.h>
#include <ds.h>


/* key lengths */
#define AES_KEY_BITS            256 
#define AES_KEY_LEN             (AES_KEY_BITS/8)
#define AES_IV_BITS             128
#define AES_IV_LEN              (AES_IV_BITS/8)
#define SM4_KEY_BITS            128
#define SM4_KEY_LEN             (SM4_KEY_BITS/8)
#define IBE_MPK_LEN             237
#define IBE_SK_LEN              380
#define IBE_SIGN_LEN            72



/*
 * cbc 
 */



int put_iv_fp(const char* filename, const char* iv, size_t len);
int get_iv_fp(const char* filename, char* iv, size_t len);
int gen_random_iv(char *iv);
int gen_random_key(char *key);
int run_ibe_verify(struct SignMesg *sig, IBEPublicParameters *mpk, const char *id, size_t id_len);

void gen_random_sm4(unsigned char *key);
void set_key(unsigned char *key, FILE* filename);
void get_key(unsigned char *key, FILE* filename);

int sym_crypt_ecb(unsigned char key[16], int mode,
					 int length,
                     unsigned char *input,
                     unsigned char *output,
                     int *output_length);

char *hash_sm3_py(char *m, long m_len);


#ifdef __cplusplus
}
#endif
#endif 

