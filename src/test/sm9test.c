#include <stdio.h>
#include <string.h>

# include <openssl/evp.h>
# include <openssl/err.h>
# include <openssl/rand.h>

#include "../crypto/crypto.h"

#define BUFF_SIZE 1024

char mpk_filename[] = "mpk.conf";
char msk_filename[] = "msk.conf";
char sk_filename[] = "sk_Server.conf";
char id[] = "Server";
char data[BUFF_SIZE] = "This is a test text";
char c_buf[BUFF_SIZE] = {'\0'};
char out[BUFF_SIZE] = {'\0'};
char out_read[BUFF_SIZE] = {'\0'};

size_t c_len, out_len;

SM9PublicParameters *mpk;
SM9MasterSecret *msk;
SM9PrivateKey *sk;
SM9PrivateKey *sk_read;

int test_set_up() {
    printf("[test] set up function\n");

    return system_setup(mpk_filename, msk_filename);
}

int test_get_public_parameters() {
    printf("[test] get pulic mpk from file\n");
    mpk = SM9PublicParameters_new();
    return get_mpk_fp(mpk_filename, mpk);
}

int test_get_master_secret() {
    printf("[test] get msk from file\n");
    msk = SM9MasterSecret_new();                    // init
    return get_msk_fp(msk_filename, msk);    
}

int test_extract_private_key() {
    printf("[test] extract private key\n");
    sk = extract_private_key(msk, id);
    if (!sk) 
        return -1;
    return 0;
}

int test_get_private_key() {
    printf("[test] get private key\n");
    size_t data_len = strlen(data);

    sk_read = SM9PrivateKey_new();
    if(-1 == get_sk_fp(sk_filename, sk_read)) 
        return -1;    
    // 用读取的密钥解密一次结果
    
    out_len = BUFF_SIZE;
    if(-1 == sm9_decrypt(c_buf, c_len, out_read, &out_len, sk))     // 解密 
        return -1;

    printf("\t%s\n", data);
    printf("\t%s\n", out_read);

    if(data_len!=out_len || memcmp(data, out_read, out_len)!=0)  // 比较明文
        return -1;
}

int test_put_private_key() {
    printf("[test] put private key\n");
    return put_sk_fp(sk_filename, sk);
}

int test_sm9_encrypt() {
    printf("[test] encrypt\n");
    size_t data_len = strlen(data);
    size_t id_len = strlen(id);
    return sm9_encrypt(data, data_len, c_buf, &c_len, mpk, id, id_len);
}

int test_sm9_decrypt() {
    printf("[test] decrypt\n");
    size_t data_len = strlen(data);

    out_len = BUFF_SIZE;             // 坑！ 这个必须选个大一些的值，不然会出现buff太小的错
    int ret = sm9_decrypt(c_buf, c_len, out, &out_len, sk);
    printf("\t%s\n", data);
    printf("\t%s\n", out);
    
    if(-1 == ret) 
        return ret;
    if(data_len!=out_len || memcmp(data, out, out_len)!=0) 
        return -1;
}

int main(int argc, char *argv[]) {

    if(-1 == test_set_up()) goto end; 
    if(-1 == test_get_public_parameters()) goto end;
    if(-1 == test_get_master_secret()) goto end; 
    if(-1 == test_extract_private_key()) goto end; 
    if(-1 == test_sm9_encrypt()) goto end; 
    if(-1 == test_sm9_decrypt()) goto end; 
    
    if(-1 == test_put_private_key()) goto end; 
    if(-1 == test_get_private_key()) goto end; 

    printf("[test] pass \n");
    return 0; 
end: 
    SM9PublicParameters_free(mpk);
    SM9MasterSecret_free(msk);
    SM9PrivateKey_free(sk);
    SM9PrivateKey_free(sk_read);
    printf("[test] fail \n");
    return -1;
}
