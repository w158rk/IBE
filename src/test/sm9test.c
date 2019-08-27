#include <stdio.h>
#include <string.h>

# include <openssl/evp.h>
# include <openssl/err.h>
# include <openssl/rand.h>

#include <crypto.h>
#include <config.h>
#include <sys.h>

// char mpk_filename[] = "mpk.conf";
// char msk_filename[] = "msk.conf";
char sk_filename[] = "sk_Server.conf";
// char id[] = "Server";
char data[BUFFER_SIZE] = "This is a test text";
char c_buf[BUFFER_SIZE] = {'\0'};
char out[BUFFER_SIZE] = {'\0'};
char out_read[BUFFER_SIZE] = {'\0'};

size_t c_len, out_len;

IBEPublicParameters mpk;
IBEMasterSecret msk;
IBEPrivateKey sk;
IBEPrivateKey sk_read;

int test_set_up() {
    printf("[test] set up function\n");
    return sys_setup(MPK_FILENAME, MSK_FILENAME);
}

int test_get_public_parameters() {
    printf("[test] get pulic mpk from file\n");
    return get_mpk_fp(MPK_FILENAME, &mpk);
}

int test_get_master_secret() {
    printf("[test] get msk from file\n");
    return get_msk_fp(MSK_FILENAME, &msk);    
}

int test_extract_private_key() {
    printf("[test] extract private key\n");
    if (0 == ibe_extract(&sk, &msk, SERVER_ID, SERVER_ID_LEN)) 
        return -1;
    return 0;
}

int test_get_private_key() {
    printf("[test] get private key\n");
    size_t data_len = strlen(data);

    if(-1 == get_sk_fp(sk_filename, &sk_read)) 
        return -1;    

    // 用读取的密钥解密一次结果
    out_len = BUFFER_SIZE;
    if(-1 == ibe_decrypt(c_buf, c_len, out_read, &out_len, &sk_read))     // 解密 
        return -1;

    printf("\t%s\n", data);
    printf("\t%s\n", out_read);

    if(data_len!=out_len || memcmp(data, out_read, out_len)!=0)  // 比较明文
        return -1;
}

int test_put_private_key() {
    printf("[test] put private key\n");
    return put_sk_fp(sk_filename, &sk);
}

int test_sm9_encrypt() {
    printf("[test] encrypt\n");
    size_t data_len = strlen(data);
    return ibe_encrypt(data, data_len, c_buf, &c_len, &mpk, SERVER_ID, SERVER_ID_LEN);
}

int test_sm9_decrypt() {
    printf("[test] decrypt\n");
    size_t data_len = strlen(data);

    out_len = BUFFER_SIZE;             // 坑！ 这个必须选个大一些的值，不然会出现buff太小的错
    int ret = ibe_decrypt(c_buf, c_len, out, &out_len, &sk);
    printf("\t%s\n", data);
    printf("\t%s\n", out);
    
    if(0 == ret) {
        ERROR("error in decrypt");
        goto end;
    } 
    if(data_len!=out_len || memcmp(data, out, out_len)!=0)  {
        ERROR("difference between the plain text and the decrypted text");
        fprintf(stderr, "outlen : %d, datalen : %d", out_len, data_len);
        goto end;
    }
    return 0;

end:
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
    printf("[test] fail \n");
    return -1;
}
