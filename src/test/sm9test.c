#include <stdio.h>
#include <string.h>

# include <openssl/evp.h>
# include <openssl/err.h>
# include <openssl/rand.h>

#include <crypto.h>
#include <config.h>
#include <sys.h>

#define MPK_FILENAME "mpk-Server.conf"
#define MSK_FILENAME "msk.conf"
#define MSK_LEN_FILENAME "msk-len.conf"
#define MPK_LEN_FILENAME "mpk-len.conf"
#define SERVER_ID "Server"
#define SERVER_ID_LEN 6


char sk_filename[] = "sk_Server.conf";
// char id[] = "Server";
char data[BUFFER_SIZE] = "This is a test text";
char data2[BUFFER_SIZE] = "This is a sign test";
char c_buf[BUFFER_SIZE] = {'\0'};
char out[BUFFER_SIZE] = {'\0'};
char out_read[BUFFER_SIZE] = {'\0'};
char sign_data[BUFFER_SIZE] = {'\0'};

size_t c_len, out_len, sign_len;

IBEPublicParameters mpk = NULL;
IBEMasterSecret msk = NULL;
IBEPrivateKey sk = NULL;
IBEPrivateKey sk_read = NULL;

int test_set_up() {
    printf("[test] set up function\n");
    return ibe_setup(MPK_FILENAME, MSK_FILENAME,MPK_LEN_FILENAME, MSK_LEN_FILENAME);   //系统建立得到mpk.conf，msk_conf
}

int test_get_public_parameters() {
    printf("[test] get pulic mpk from file\n");
    return get_mpk_fp(MPK_FILENAME, &mpk);  //获取sP存放在mpk.conf中
}

int test_get_master_secret() {
    printf("[test] get msk from file\n");
    return get_msk_fp(MSK_FILENAME, &msk);      //获取s存放在msk.conf中
}

int test_extract_private_key() {
    printf("[test] extract private key\n");
    long len = BUFFER_SIZE;
    if (0 == ibe_extract(&sk, &len, &msk, 273, SERVER_ID, SERVER_ID_LEN))  //生成私钥存放在sk中
        return -1;
#ifdef DEBUG 
    fprintf(stderr, "len of sk: %ld\n", len);
#endif
    return 0;
}

int test_get_private_key() {
    printf("[test] get private key\n");
    size_t data_len = strlen(data);

    sk_read = NULL;
    if(!get_sk_fp(sk_filename, &sk_read))  //从sk_Server.conf读取私钥放入sk_read中
        return -1;    

    // 用读取的密钥解密一次结果
    out_len = BUFFER_SIZE;
    if(!ibe_decrypt(c_buf, c_len, out_read, &out_len, &sk_read, 380))     // 解密 
        return -1;

    printf("\t%s\n", data);
    printf("\t%s\n", out_read);

    if(data_len!=out_len || memcmp(data, out_read, out_len)!=0)  // 比较明文
        return -1;
}

int test_put_private_key() {
    printf("[test] put private key\n");
    return put_sk_fp(sk_filename, &sk, 380); //将sk输出在sk_Server.conf中
}

int test_smx_encrypt() {
    printf("[test] encrypt\n");
    size_t data_len = strlen(data);
    c_len = BUFFER_SIZE;
    return ibe_encrypt(data, data_len, c_buf, &c_len, &mpk,239, SERVER_ID, SERVER_ID_LEN);  //ibe加密算法
}

int test_smx_decrypt() {
    printf("[test] decrypt\n");
    size_t data_len = strlen(data);

    out_len = BUFFER_SIZE;             // 坑！ 这个必须选个大一些的值，不然会出现buff太小的错
    int ret = ibe_decrypt(c_buf, c_len, out, &out_len, &sk, 380);    //解密算法
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

int test_smx_sign()
{
    fprintf(stderr, "[test] sign\n");

    size_t data_len = strlen(data2);
    int ret = 0;

    sign_len = BUFFER_SIZE;

    if(!(ibe_sign(data2, data_len, sign_data, &sign_len, &sk, 380)))
    {
        fprintf(stderr, "sign error\n");
        goto end;
    }

    ret = 1;

end:
    return ret;
}

int test_smx_verify()
{
    printf("[test] verify\n");
    size_t data_len = strlen(data2);
    int ret = 0;

    if(!ibe_verify(data2, data_len, sign_data, sign_len, &mpk, 239, SERVER_ID, SERVER_ID_LEN))
    {
        fprintf(stderr, "verify error\n");
        goto end;
    }

    ret = 1;

end:
    return ret;
}

/*void print(char* data)
{
    printf("data is%s\n",data);
}*/

int main(int argc, char *argv[]) {

    if(-1 == test_set_up()) goto end; 
    if(-1 == test_get_public_parameters()) goto end;    //获取sP，并输出文件
    if(-1 == test_get_master_secret()) goto end;    //获取s，并输出文件
    if(-1 == test_extract_private_key()) goto end;  //获取sk

    if(-1 == test_smx_encrypt()) goto end;  //加密
    if(-1 == test_smx_decrypt()) goto end;  //解密 

    // if(-1 == test_smx_encrypt()) goto end;  //加密
    // if(-1 == test_smx_decrypt()) goto end;  //解密 
    // if(-1 == test_put_private_key()) goto end;  //加密
    // if(-1 == test_get_private_key()) goto end;  //解密 

    // if(-1 == test_smx_encrypt()) goto end;  //加密
    // if(-1 == test_smx_decrypt()) goto end;  //解密 

    // if(-1 == test_smx_encrypt()) goto end;  //加密
    // if(-1 == test_put_private_key()) goto end;  //加密
    // if(-1 == test_get_private_key()) goto end;  //解密 
    // if(-1 == test_get_public_parameters()) goto end;    //获取sP，并输出文件
    if(0 == test_smx_sign()) goto end;  //解密 
    if(0 == test_smx_verify()) goto end;  //解密 

    //print(data2);
    //int i = test_smx_sign();
    // size_t data_len = strlen(data2);
    // int ret = SMX_sign(NID_sm3, data2, data_len, &sign_data, &sign_len, sk);
    // printf("ret is%d\n", ret);
    // printf("sign is%s\n", sign_data);
    // printf("sign length is%d\n", sign_len);
    /*int ret = test_smx_verify();
    printf("ret is%d\n", ret);*/

    printf("[test] pass \n");
    return 0; 
end: 
    printf("[test] fail \n");
    return -1;
}
