#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Enable ECB, CTR and CBC mode. Note this can be done before including aes.h or at compile-time.
// E.g. with GCC by using the -D flag: gcc -c aes.c -DCBC=0 -DCTR=1 -DECB=1
#include "aes.h"

#ifdef AES256
#define SIZE 32
#endif

// #define DEBUG

// use cbc 256

int main(int argc, char * argv[]) {
    // in, key, iv, out
    char in[SIZE+1]={0};
    char key[SIZE+1]={0}; 
    char iv[AES_BLOCKLEN+1]={0};
    
    if(argc != 5) {
        printf("4 arguments needed");
        exit(1);
    }
    FILE *fp = fopen(argv[1], "rb");
    fread(in, SIZE, 1, fp);
    fclose(fp);
    #ifdef DEBUG 
    printf("%s\n", in);
    #endif    

    fp = fopen(argv[2], "rb");
    fread(key, SIZE, 1, fp);
    fclose(fp);
    #ifdef DEBUG 
    printf("%s\n", key);
    #endif       

    fp = fopen(argv[3], "rb");
    fread(iv, AES_BLOCKLEN, 1, fp);
    fclose(fp);
    #ifdef DEBUG 
    printf("%s\n", iv);
    #endif    

    struct AES_ctx ctx;

    AES_init_ctx_iv(&ctx, key, iv);
    AES_CBC_encrypt_buffer(&ctx, in, SIZE);
        #ifdef DEBUG 
    printf("iv:%s\n", iv);
    printf("%s\n", in);
    AES_init_ctx_iv(&ctx, key, iv);
    AES_CBC_decrypt_buffer(&ctx, in, SIZE);
        printf("iv:%s\n", iv);
    printf("%s\n", in);
    #endif    



    fp = fopen(argv[4], "wb");
    fwrite(in, SIZE, 1, fp);
    fclose(fp);
}