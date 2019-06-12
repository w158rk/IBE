#include <stdio.h>
#include <string.h>

# include <openssl/evp.h>
# include <openssl/err.h>
# include <openssl/rand.h>

#include "../crypto/crypto.h"

unsigned char iv_read[32]  = {'\0'};;
char filename[] = "iv.conf";
size_t len=16, m_len, c_len;

unsigned char *plaintext =(unsigned char *)"The quick brown fox jumps over the lazy dog";
unsigned char *iv = NULL;/*(unsigned char *)"0123456789012345";*/
unsigned char *key = NULL;/*(unsigned char *)"01234567890123456789012345678901";*/
unsigned char ciphertext[128];
unsigned char decryptedtext[128];

int test_put_iv_fp(){
    printf("[test] put iv to file...\n");
    return put_iv_fp(filename, iv, len);
}

int test_get_iv_fp(){
    printf("[test] get iv from file...\n");
    
    if(-1 == get_iv_fp(filename, iv_read, len)) return -1;

    printf("\t%s\n", iv);
    printf("\t%s\n", iv_read);
    if(memcmp(iv, iv_read, len) != 0) return -1;
    
    return 0;
}

int test_encrypt() {
    printf("[test] encrypt...\n");
    if(-1 == cbc_encrypt(plaintext, strlen(plaintext), key, iv, ciphertext, &c_len)) return -1;

    return 0;
}

int test_decrypt() {
    printf("[test] decrypt...\n");
    if(-1 == cbc_decrypt(ciphertext, c_len, key, iv, decryptedtext, &m_len)) return -1;

    printf("\t%s\n", plaintext);
    printf("\t%s\n", decryptedtext);
    if(m_len != strlen(plaintext) || 0 != memcmp(decryptedtext, plaintext, m_len)) return -1;

    return 0;
}

int test_gen_key() {
    printf("[test] generate key...\n");
    if(0 != gen_random_key(key)) return -1;

    printf("\tkey : %s\n", key);
    return 0;
}

int test_gen_iv() {
    printf("[test] generate iv...\n");
    if(0 != gen_random_iv(iv)) return -1;
    
    printf("\tiv : %s\n", iv);
    return 0;
}

int main(int argc, char *argv[]) {
    iv = (char *)malloc(128/8+1);   
    iv[128/8] = '\0';
    key = (char *)malloc(256/8+1);
    key[256/8] = '\0';

    if(-1 == test_gen_iv()) goto end;
    if(-1 == test_gen_key()) goto end;
    if(-1 == test_put_iv_fp()) goto end;
    if(-1 == test_get_iv_fp()) goto end;
    if(-1 == test_encrypt()) goto end;
    if(-1 == test_decrypt()) goto end;

    printf("test passed\n");
    return 0;
end :
    printf("test failed\n");
    return -1;
} 