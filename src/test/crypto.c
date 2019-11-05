#include <stdio.h>
#include <string.h>

# include <openssl/evp.h>
# include <openssl/err.h>
# include <openssl/rand.h>

#include <crypto.h>
#include <sys.h>

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

IBEPublicParameters mpk;
IBEMasterSecret msk;
IBEPrivateKey sk;
IBEPrivateKey sk_read;

int test_set_up() {
    printf("[test] set up function\n");

    return sys_setup(mpk_filename, msk_filename);
}

int test_get_public_parameters() {
    printf("[test] get pulic mpk from file\n");
    int ret = get_mpk_fp(mpk_filename, &mpk);
    return ret; 
}

int test_get_master_secret() {
    printf("[test] get msk from file\n");
    int ret = get_msk_fp(msk_filename, &msk);   
    return ret; 
}

int test_extract_private_key() {
    printf("[test] extract private key\n");
    int rtn = ibe_extract(&sk, &msk, id, 6);
    if (!rtn) 
        return 0;
    return 1;
}

int test_get_private_key() {
    printf("[test] get private key\n");
    size_t data_len = strlen(data);

    if(0 == get_sk_fp(sk_filename, &sk_read)) 
        return 0;    
    
    out_len = BUFF_SIZE;
    if(0 == ibe_decrypt(c_buf, c_len, out_read, &out_len, &sk_read))     // 解密 
        return 0;

    printf("\t%s\n", data);
    printf("\t%s\n", out_read);

    if(data_len!=out_len || memcmp(data, out_read, out_len)!=0)  // 比较明文
        return 0;
    
    return 1;
}

int test_put_private_key() {
    printf("[test] put private key\n");
    #ifdef DEBUG 
    int i;
    for(i=0; i<IBE_SK_LEN; i++) {
        fprintf(stderr, "%02x ", sk[i] & 0xff);
    }
    fprintf(stderr, "\n ");
    #endif
    return put_sk_fp(sk_filename, &sk);
}

int test_sm9_encrypt() {
    printf("[test] encrypt\n");
    size_t data_len = strlen(data);
    size_t id_len = strlen(id);
    return ibe_encrypt(data, data_len, c_buf, &c_len, &mpk, id, id_len);
}

int test_sm9_decrypt() {
    printf("[test] decrypt\n");
    size_t data_len = strlen(data);

    out_len = BUFF_SIZE;             // 坑！ 这个必须选个大一些的值，不然会出现buff太小的错
    #ifdef DEBUG 
    fprintf(stderr, "test : %ld\n", sk);
    fprintf(stderr, "\tc length : %d\n", c_len);
    #endif
    int ret = ibe_decrypt(c_buf, c_len, out, &out_len, &sk);
    printf("\t%s\n", data);
    printf("\t%s\n", out);
    printf("\t%d\n", out_len);
    
    if(0 == ret) 
        return 0;
    if(data_len!=out_len || memcmp(data, out, out_len)!=0) 
        return 0;
    
    return 1;
}

int main(int argc, char *argv[]) {

    if(0 == test_set_up()) goto end; 
    if(0 == test_get_public_parameters()) goto end;
    if(0 == test_get_master_secret()) goto end; 
    if(0 == test_extract_private_key()) goto end; 
    if(0 == test_sm9_encrypt()) goto end; 
    if(0 == test_sm9_decrypt()) goto end; 
    
    if(0 == test_put_private_key()) goto end; 
    if(0 == test_get_private_key()) goto end; 

    ERROR("[test] pass \n");
    return 0; 
end: 
    ERROR("[test] fail \n");
    return -1;
}
