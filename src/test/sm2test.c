#include <stdio.h>
#include <string.h>

# include <openssl/evp.h>
# include <openssl/sm2.h>
# include <openssl/err.h>
# include <openssl/rand.h>

#include <crypto.h>
#include <config.h>
#include <sys.h>
#include <time.h>


char data[BUFFER_SIZE] = "This is a test text";
char data2[BUFFER_SIZE] = "This is a sign test";
char c_buf[BUFFER_SIZE] = {'\0'};
char out[BUFFER_SIZE] = {'\0'};
char out_read[BUFFER_SIZE] = {'\0'};
char sign_data[BUFFER_SIZE] = {'\0'};
const EVP_MD *md;

clock_t cur_time;

size_t c_len, out_len, sign_len;

EC_KEY *eckey;


int test_set_up() {
    printf("[test] set up function\n");
    if (!(eckey = EC_KEY_new_by_curve_name(NID_sm2p256v1))) {
        goto end;
    }
    if (!EC_KEY_generate_key(eckey)) {
        fprintf(stderr, "unable to generate key\n");
        EC_KEY_free(eckey);
        goto end;
    }
    return 1;
end:
    return 0;
}


int test_sm2_encrypt() {
	int ret = 0;
	SM2CiphertextValue *cval = NULL;
    char *cbuf;

    cur_time = clock();
	if (!(cval = SM2_do_encrypt(md, data, sizeof(data), eckey))
		|| i2d_SM2CiphertextValue(cval, &cbuf) <= 0) {
        fprintf(stderr, "error in encrypt\n");
		goto end;
	}
    printf("time for encrypt: %ld\n", clock()-cur_time);

    memcpy(c_buf, cbuf, sizeof(cbuf));
    c_len = sizeof(cbuf);

	ret = 1;

end:
	// SM2CiphertextValue_free(cval);
	// free(cbuf);
	return ret;
}

int test_sm2_decrypt() {

	int ret = 0;
	SM2CiphertextValue *cval = NULL;
	unsigned char *buf = NULL;
	size_t siz;

    cur_time = clock();
	if (!(cval = d2i_SM2CiphertextValue(&cval, &c_buf, c_len))
		|| !SM2_do_decrypt(md, cval, NULL, &siz, eckey)
		|| !(buf = OPENSSL_malloc(siz))
		|| !SM2_do_decrypt(md, cval, buf, &siz, eckey)
		|| BIO_write(out, buf, siz) != siz) {
		goto end;
	}
    printf("time for encrypt: %ld\n", clock()-cur_time);
	ret = 1;

end:
	// SM2CiphertextValue_free(cval);
	// OPENSSL_free(buf);
	return ret;

}

// int test_sm2_sign()
// {
//     fprintf(stderr, "[test] sign\n");

//     size_t data_len = strlen(data2);
//     int ret = 0;

//     sign_len = BUFFER_SIZE;

//     cur_time = clock();
//     if(!(ibe_sign(data2, data_len, sign_data, &sign_len, &sk, 381)))
//     {
//         fprintf(stderr, "sign error\n");
//         goto end;
//     }
//     printf("time for sign: %ld\n", clock()-cur_time);

//     ret = 1;

// end:
//     return ret;
// }

// int test_sm2_verify()
// {
//     printf("[test] verify\n");
//     size_t data_len = strlen(data2);
//     int ret = 0;

//     cur_time = clock();
//     if(!ibe_verify(data2, data_len, sign_data, sign_len, &mpk, 239, SERVER_ID, SERVER_ID_LEN))
//     {
//         fprintf(stderr, "verify error\n");
//         goto end;
//     }
//     printf("time for verif: %ld\n", clock()-cur_time);

//     ret = 1;

// end:
//     return ret;
// }

/*void print(char* data)
{
    printf("data is%s\n",data);
}*/

int main(int argc, char *argv[]) {

    md = EVP_sm3();

    if(-1 == test_set_up()) goto end; 

    // if(-1 == test_sm2_encrypt()) goto end;  //加密
    // if(-1 == test_sm2_decrypt()) goto end;  //解密 

    if(-1 == test_sm2_encrypt()) goto end;  //加密
    if(-1 == test_sm2_decrypt()) goto end;  //解密 
    // if(-1 == test_put_private_key()) goto end;  //加密
    // if(-1 == test_get_private_key()) goto end;  //解密 

    // if(-1 == test_sm2_encrypt()) goto end;  //加密
    // if(-1 == test_sm2_decrypt()) goto end;  //解密 

    // if(-1 == test_sm2_encrypt()) goto end;  //加密
    // if(-1 == test_put_private_key()) goto end;  //加密
    // if(-1 == test_get_private_key()) goto end;  //解密 
    // if(-1 == test_get_public_parameters()) goto end;    //获取sP，并输出文件
    // if(0 == test_sm2_sign()) goto end;  //解密 
    // if(0 == test_sm2_verify()) goto end;  //解密 

    //print(data2);
    //int i = test_sm2_sign();
    // size_t data_len = strlen(data2);
    // int ret = sm2_sign(NID_sm3, data2, data_len, &sign_data, &sign_len, sk);
    // printf("ret is%d\n", ret);
    // printf("sign is%s\n", sign_data);
    // printf("sign length is%d\n", sign_len);
    /*int ret = test_sm2_verify();
    printf("ret is%d\n", ret);*/

    printf("[test] pass \n");
    return 0; 
end: 
    printf("[test] fail \n");
    return -1;
}
