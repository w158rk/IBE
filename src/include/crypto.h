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

#include <openssl/sm4.h>

#include <ibe.h>


/* key lengths */
#define AES_KEY_BITS            256 
#define AES_KEY_LEN             (AES_KEY_BITS/8)
#define AES_IV_BITS             128
#define AES_IV_LEN              (AES_IV_BITS/8)
#define SM4_KEY_BITS            128
#define SM4_KEY_LEN             (SM4_KEY_BITS/8)
#define IBE_MPK_LEN             237




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

