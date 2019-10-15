#include <packet.h>
#include <stdio.h>
#include <crypto.h>
#include <sys.h>
#include <ctx.h>
#include <string.h>
#include <openssl/sm4.h>
//#define DEBUG

int handle_dec(PacketCTX *ctx) {

    AppPacket app_packet;
    AppPacket *p_sk_packet = ctx->payload.secPacket->payload.appPacket;
    #ifdef DEBUG
    fprintf(stderr, "enc_sk is%s\n", ctx->payload.secPacket->payload.sk_data);
    #endif
    SecPacket *p_sec_packet = ctx->payload.secPacket;

    int ret = 0;

    char m[BUFFER_SIZE];
    int c_len = 0;          // declaration
    int m_len = BUFFER_SIZE;
    int payload_len = BUFFER_SIZE;

    char *filename = NULL;
    int filename_len = 0;
    IBEPrivateKey sk = NULL;

    int crypto_type = *(int *)(p_sec_packet->head);
    #ifdef DEBUG 
    fprintf(stderr, "type : %d\n", crypto_type);
    fprintf(stderr, "message length : %d\n", *(int *)(p_sec_packet->head+4));
    #endif
    switch (crypto_type)
    {
    case NO_ENC_TYPE:
        /* code */
        break;
    case IBE_TYPE:
        c_len = *(int *)(p_sec_packet->head+4);
        filename_len = ctx->dest_id_len + 9;
        filename = (char *)malloc(filename_len);
        filename[0] = 's';
        filename[1] = 'k';
        filename[2] = '_';
        memcpy(filename+3, ctx->dest_id, ctx->dest_id_len);
        filename[filename_len-6] = '.'; 
        filename[filename_len-5] = 'c'; 
        filename[filename_len-4] = 'o'; 
        filename[filename_len-3] = 'n'; 
        filename[filename_len-2] = 'f';
        filename[filename_len-1] = '\0';
        if (!get_sk_fp(filename, &sk) 
            ||!ibe_decrypt(p_sec_packet->payload.data, c_len, m, &m_len, &sk))
        {
            ERROR("decrypt fail");
            goto end;
        };

        #ifdef DEBUG 
        fprintf(stderr, "filename is%s\n", filename);
        fprintf(stderr, "message length : %d\n", m_len); 
        fprintf(stderr, "type : %d\n", *(int *)m);
        #endif

        // make the app packet 
        memcpy(app_packet.head, m, APP_HEAD_LEN);       //head中放入解密前8位的内容
        payload_len = *(int *)(m+4);                // get the length of the payload 

        char *payload = (char *)malloc(payload_len);
        memcpy(payload, m+APP_HEAD_LEN, payload_len);
        app_packet.payload = payload;       //payload中放入解密后8位的内容

        #ifdef DEBUG 
        fprintf(stderr, "payload length : %d\n", payload_len);
        fprintf(stderr, "payload : %s\n", payload);
        #endif

        // add the app packet to the payload of the sec packet 
        p_sec_packet->payload.appPacket = &app_packet;
        break;
   
    case SM4_TYPE:
    {
        #ifdef DEBUG
        printf("the public key is:");
        for(int t=0;t<16;t++)
            printf("%02x ",sm4key[t]);
        printf("\n");
        #endif
        sm4_context sm4ctx;
        sm4_setkey_dec(&sm4ctx, sm4key);
        int N = strlen(p_sec_packet->payload.data);
        #ifdef DEBUG
        fprintf(stderr, "len is %d\n",N);
        #endif
        unsigned char *sk = (unsigned char *)malloc(IBE_SK_LEN);
	    sm4_crypt_ecb(&sm4ctx, 0, IBE_SK_LEN, p_sec_packet->payload.sk_data,sk);
        #ifdef DEBUG
        fprintf(stderr, "id为：%s\n",ctx->dest_id);
		fprintf(stderr, "解密得到sk：%s\n",sk);
        fprintf(stderr, "私钥的长度为：%d\n",strlen(p_sec_packet->payload.data));
        #endif
        
        int filename_len2 = ctx->dest_id_len + 9;
        char *filename2 = (char *)malloc(filename_len2);
        filename2[0] = 's';
        filename2[1] = 'k';
        filename2[2] = '_';
        memcpy(filename2 + 3, ctx->dest_id, ctx->dest_id_len);
        filename2[filename_len2-6] = '.'; 
        filename2[filename_len2-5] = 'c'; 
        filename2[filename_len2-4] = 'o'; 
        filename2[filename_len2-3] = 'n'; 
        filename2[filename_len2-2] = 'f';
        filename2[filename_len2-1] = '\0';
        #ifdef DEBUG
        fprintf(stderr, "sk_filename is%s\n", filename2);
        #endif
        FILE *fp2;
        if((fp2=fopen(filename2,"wb+"))==NULL)
        {
            printf("file cannot open \n");  
        }
        fprintf(fp2, "%s", sk);
        fclose(fp2);
        fprintf(stderr,"私钥生成文件完成\n");

        *(int *)(p_sec_packet->payload.appPacket->head) = PRIVATE_KEY_RESPONSE_TYPE;

        break;
    }
        
    default:
        break;
    }

    ctx->phase = RECV_VERIFY;
    ret = 1;
end:
    free(filename);
    #ifdef DEBUG 
    fprintf(stderr, "return test\n");
    #endif
    return ret;
}