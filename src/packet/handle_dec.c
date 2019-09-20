#include <packet.h>
#include <stdio.h>
#include <crypto.h>
#include <sys.h>
#include <string.h>
#include <openssl/sm4.h>
#define DEBUG

int handle_dec(PacketCTX *ctx) {

    AppPacket app_packet;
    AppPacket *p_sk_packet = ctx->payload.secPacket->payload.appPacket;
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
        fprintf(stderr, "message length : %d\n", m_len);
        fprintf(stderr, "type : %d\n", *(int *)m);
        #endif

        // make the app packet 
        memcpy(app_packet.head, m, APP_HEAD_LEN);
        payload_len = *(int *)(m+4);                // get the length of the payload 

        char *payload = (char *)malloc(payload_len);
        memcpy(payload, m+APP_HEAD_LEN, payload_len);
        app_packet.payload = payload;

        #ifdef DEBUG 
        fprintf(stderr, "payload length : %d\n", payload_len);
        fprintf(stderr, "payload : %s\n", payload);
        #endif

        // add the app packet to the payload of the sec packet 
        p_sec_packet->payload.appPacket = &app_packet;
        break;
    case SM4_TYPE:
    {
        /* 获取sm4_key */
        unsigned char key[SM4_KEY_LEN];
        /*int filename_len = id_len + 10;
        char *filename = (char *)malloc(filename_len);
        filename[0] = 's';
        filename[1] = 'm';
        filename[2] = '4';
        filename[3] = '_';
        memcpy(filename+4, id, id_len);
        filename[filename_len-6] = '.'; 
        filename[filename_len-5] = 'c'; 
        filename[filename_len-4] = 'o'; 
        filename[filename_len-3] = 'n'; 
        filename[filename_len-2] = 'f';
        filename[filename_len-1] = '\0';*/
        FILE *fp;
        if((fp=fopen("sm4_Client.conf","rb+"))==NULL)
        {
            printf("file cannot open \n");  
        }
        get_key(key, fp);
        #ifdef DEBUG
        printf("从文件中读出key:");
        for(int t=0;t<16;t++)
            printf("%02x ",key[t]);
        printf("\n");
        #endif
        fclose(fp);

        sm4_context sm4ctx;
        sm4_setkey_dec(&sm4ctx,key);
        int N = strlen(p_sk_packet->payload);
        fprintf(stderr, "len is %d\n",N);
	    /*sm4_crypt_ecb(&sm4ctx,0,N,app_packet.payload,app_packet.payload);
        #ifdef DEBUG
        printf("解密得到：");
	    for(int i=0;i<N;i++)
		    printf("%s",app_packet.payload);
	    printf("\n");
        #endif*/

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