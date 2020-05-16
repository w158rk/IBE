#include <crypto.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

// 
/*
int main()
{
	//char x;
    unsigned char key[16];
    char filename[50];
	printf("输入文件名:");
	fgets(filename, 100000, stdin);
    FILE *fp;
    if((fp=fopen(filename,"wb+"))==NULL)
    {
        printf("file cannot open \n");
        
    }
    set_key(key,fp);
	fclose(fp);
    unsigned char input[100000];
	unsigned char output[100000];
	sm4_context ctx;
	int N,choice,t;
	unsigned long i;
	printf("初始key:");
	for(t=0;t<16;t++)
		printf("%02x ",key[t]);
	printf("\n");
    char filename2[50];
	printf("输入文件名:");
	fgets(filename2, 100000, stdin);
    FILE *fp2;
    if((fp2=fopen(filename2,"rb+"))==NULL)
    {
        printf("file cannot open \n");  
    }
	get_key(key, fp2);
	printf("从文件中读出key:");
	for(t=0;t<16;t++)
		printf("%02x ",key[t]);
	printf("\n");
    fclose(fp2);
    printf("输入需要加密的字符串：");
    N=choice1(input);
    printf("明文长度：%d\n",N);

	//encrypt standard testing vector
	sm4_setkey_enc(&ctx,key);
	int out_len;
	sm4_crypt_ecb(&ctx,1,N,input,output,&out_len);
	printf("加密得到：");
	for(i=0;i<N;i++)
		printf("%02x ", output[i]);
	printf("\n");
 
	//decrypt testing
	sm4_setkey_dec(&ctx,key);
	sm4_crypt_ecb(&ctx,0,N,output,output,&out_len);
	printf("解密得到：");
	for(i=0;i<N;i++)
		printf("%c", output[i]);
	printf("\n");

    return 0;
}
*/

int main() 
{
	unsigned char *key 	= "1234567812345678";
	char *m 		= "hello";
	char c[50];
	char dec_m[50];
	int c_len = 50;
	int dec_m_len = 50;

	sym_crypt_ecb(key, 1, 5, m, c, &c_len);
	printf("clen: %d\n", c_len);
	sym_crypt_ecb(key, 0, c_len, c, dec_m, &dec_m_len);
	printf("dec_len: %d\n", dec_m_len);
	dec_m[dec_m_len] = '\0';
	printf("dec_len: %s\n", dec_m);

}