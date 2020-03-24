#include <stdio.h>
#include <string.h>

# include <openssl/evp.h>
# include <openssl/err.h>
# include <openssl/rand.h>
# include <openssl/sm9.h>

#include <crypto.h>
#include <config.h>
#include <sys.h>
#include <time.h>

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

size_t c_len, out_len, sign_len, mpk_len, msk_len;
size_t sk_len =0;

SM9PublicParameters *mpk = NULL;
SM9MasterSecret *msk = NULL;
SM9PrivateKey *sk = NULL;

int test_set_up_enc() {
    printf("[test] set up function\n");
    return SM9_setup(NID_sm9bn256v1, NID_sm9encrypt, NID_sm9hash1_with_sm3, &mpk, &msk);
}

int test_set_up_sign() {
    printf("[test] set up function\n");
    return SM9_setup(NID_sm9bn256v1, NID_sm9sign, NID_sm9hash1_with_sm3, &mpk, &msk);
}

int test_extract_private_key() {
    printf("[test] extract private key\n");
    if (NULL == (sk = SM9_extract_private_key(msk, SERVER_ID, SERVER_ID_LEN)))  //生成私钥存放在sk中
        return -1;
    return 0;
}

int test_sm9_encrypt() {
    printf("[test] encrypt\n");
    size_t data_len = strlen(data);
    c_len = BUFFER_SIZE;
    return SM9_encrypt(NID_sm9encrypt_with_sm3_xor, data, data_len, c_buf, &c_len, mpk, SERVER_ID, SERVER_ID_LEN);  //ibe加密算法
}

int test_sm9_decrypt() {
    printf("[test] decrypt\n");
    size_t data_len = strlen(data);

    out_len = BUFFER_SIZE;             // 坑！ 这个必须选个大一些的值，不然会出现buff太小的错
    int ret = SM9_decrypt(NID_sm9encrypt_with_sm3_xor, c_buf, c_len, out, &out_len, sk);    //解密算法
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

int test_sm9_sign()
{
    fprintf(stderr, "[test] sign\n");

    size_t data_len = strlen(data2);
    int ret = 0;

    sign_len = BUFFER_SIZE;

    if(!(SM9_sign(NID_sm3, data2, data_len, sign_data, &sign_len, sk)))
    {
        fprintf(stderr, "sign error\n");
        goto end;
    }

    ret = 1;

end:
    return ret;
}

int test_sm9_verify()
{
    printf("[test] verify\n");
    size_t data_len = strlen(data2);
    int ret = 0;

    if(!SM9_verify(NID_sm3, data2, data_len, sign_data, sign_len, mpk, SERVER_ID, SERVER_ID_LEN))
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


    double start,end,cost;

    if(-1 == test_set_up_enc()) goto end;
    if(-1 == test_extract_private_key()) goto end;  //获取sk

    start=clock();
    if(-1 == test_sm9_encrypt()) goto end;  //加密
    end=clock();
    cost=(end-start)/CLOCKS_PER_SEC*1000;
    printf("encrypt time is: %f ms\n",cost);

    start=clock();
    if(-1 == test_sm9_decrypt()) goto end;  //解密 
    end=clock();
    cost=(end-start)/CLOCKS_PER_SEC*1000;
    printf("decrypt time is: %f ms\n",cost);


    if(-1 == test_set_up_sign()) goto end;
    if(-1 == test_extract_private_key()) goto end;  //获取sk

    start=clock();
    if(0 == test_sm9_sign()) goto end;  //解密 
    end=clock();
    cost=(end-start)/CLOCKS_PER_SEC*1000;
    printf("sign time is: %f ms\n",cost);

    start=clock();
    if(0 == test_sm9_verify()) goto end;  //解密 
    end=clock();
    cost=(end-start)/CLOCKS_PER_SEC*1000;
    printf("verify time is: %f ms\n",cost);

    // sign_len = BUFFER_SIZE;
    // size_t data_len = strlen(data2);
    // get_sk_fp("sk_Client.conf", &sk_read);
    // fprintf(stderr,"[sign]\n");
    // if(!(ibe_sign(data2, data_len, sign_data, &sign_len, &sk_read, 381)))
    // {
    //     fprintf(stderr, "sign error\n");
    //     goto end;
    // }
    // get_mpk_fp("mpkClient.conf", &mpk);
    // double start,end,cost;
    // start=clock();
    // fprintf(stderr,"[verify]\n");
    // if(!ibe_verify(data2, data_len, sign_data, sign_len, &mpk, 239, "Client", 6))
    // {
    //     fprintf(stderr, "verify error\n");
    //     goto end;
    // }
    // end=clock();
    // cost=(end-start)/CLOCKS_PER_SEC*1000;
    // printf("verify time is: %f ms\n",cost);

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
