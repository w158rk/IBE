#include <openssl/sm4.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define DEBUG

int main()
{
    unsigned char key[16];
    set_key(key);//随机生成key
	#ifdef DEBUG
	for(int i=0;i<16;i++)
	{
		printf("%x-", key[i]);
	}
	#endif
	unsigned char input[100000];
	unsigned char output[100000];
	sm4_context ctx;
    /*
	int N,choice;
	unsigned long i;
    printf("请选择明文的输入情况：1.不指定明文长度；2.指定明文长度\n");
    scanf("%d",&choice);
	switch(choice){
	  case 1:
          N=choice1(input);
		  break;
      case 2:
		  N=choice2(input);
		  break;
	  default:
		  printf("无效输入\n");
		  N=0;
		  break;
	}*/
    printf("请输入需要加密的字符串：");
    int N,i;
    N = choice1(input);
    printf("明文长度：%d\n",N);

	//encrypt standard testing vector
	sm4_setkey_enc(&ctx,key);
	sm4_crypt_ecb(&ctx,1,N,input,output);
	printf("加密得到密文：");
	for(i=0;i<N;i++)
		printf("%02x ", output[i]);
	printf("\n");
 
	//decrypt testing
	sm4_setkey_dec(&ctx,key);
	sm4_crypt_ecb(&ctx,0,N,output,output);
	printf("解密得到密文：");
	for(i=0;i<N;i++)
		printf("%c", output[i]);
	printf("\n");
 
    return 0;
}