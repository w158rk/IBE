/* 
 * GmSSL 提供的对称加密算法 
 * 作者 ： wrk 
 * 日期 ： 2019-6-12
 */

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

#include "crypto.h"

int put_iv_fp(const char* filename, const char* iv, size_t len) {
    FILE* fp = fopen(filename, "wb");
    BIO *bio = BIO_new_fp(fp, BIO_CLOSE);
    if(!BIO_write(bio, iv, len)) 
        goto end;
    fclose(fp);
    return 0; 

end : 
    fclose(fp);
    return -1;
}

int get_iv_fp(const char* filename, char* iv, size_t len) {
    FILE *fp = fopen(filename, "rb");
    BIO *bio = BIO_new_fp(fp, BIO_CLOSE);
    if(!BIO_read(bio, iv, len)) 
        goto end;
    fclose(fp);
    return 0; 

end : 
    fclose(fp);
    return -1;
}


// 256 位aes cbc
int cbc_encrypt(unsigned char *m, size_t m_len, unsigned char *key,
    unsigned char *iv, unsigned char *c, size_t* c_len)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;
    if(!(ctx = EVP_CIPHER_CTX_new())) return -1;

    /* Initialise the encryption operation. IMPORTANT - ensure you use a key
    * and IV size appropriate for your cipher
    * In this example we are using 256 bit AES (i.e. a 256 bit key). The
    * IV size for *most* modes is the same as the block size. For AES this
    * is 128 bits */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) return -1;

    /* Provide the message to be encrypted, and obtain the encrypted output.
    * EVP_EncryptUpdate can be called multiple times if necessary
    */
    if(1 != EVP_EncryptUpdate(ctx, c, &len, m, m_len)) return -1;
    ciphertext_len = len;
    /* Finalise the encryption. Further ciphertext bytes may be written at
    * this stage.
    */
    if(1 != EVP_EncryptFinal_ex(ctx, c + len, &len)) return -1;
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    *c_len = ciphertext_len;
    return 0;
}

int cbc_decrypt(unsigned char *c, size_t c_len, unsigned char *key,
    unsigned char *iv, unsigned char *m, size_t* m_len)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;
    if(!(ctx = EVP_CIPHER_CTX_new())) return -1;

    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) return -1;

    if(1 != EVP_DecryptUpdate(ctx, m, &len, c, c_len)) return -1;
    ciphertext_len = len;

    if(1 != EVP_DecryptFinal_ex(ctx, m + len, &len)) return -1;
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    *m_len = ciphertext_len;
    return 0;
}

/* 
 * 产生256位的密钥或128位的iv
 */
int gen_random_str(char *buff, size_t len/*len=32*/) {
    int i;
    for (i=0; i<len; i++) {
        char x = (char) rand();
        buff[i] = x;
    }
    return 0;
}

char* cbc_iv_new(void) {
    char *ret = (char *)malloc(AES_IV_LEN);
    return ret;
}

char* cbc_key_new(void) {
    char *ret = (char *)malloc(AES_KEY_LEN);
    return ret;
}

int gen_random_iv(char *iv) {
    return gen_random_str(iv, 128/8);
}

int gen_random_key(char *key) {
    return gen_random_str(key, 256/8);
}
