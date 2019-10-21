
extern "C" {
#include <crypto.h>
#include <sys.h>
#include <utils.h>
#include <string.h>
#include <config.h>
}

#include<packet.hpp>
#include<ds.h>

#define DEBUG

using namespace packet;
void Packet::handle_dec() {

    PacketCTX *ctx = get_ctx();

    /* packets */
    SecPacket *p_sec_packet = ctx->payload.secPacket;

    IBEPrivateKey sk = NULL;

    int crypto_type = *(int *)(p_sec_packet->head);

    switch (crypto_type)
    {
    case NO_ENC_TYPE:
        /* code */
        break;
    case IBE_TYPE:
    {
        int c_len = *(int *)(p_sec_packet->head+4);
        
        GENERATE_SK_FILENAME(ctx->dest_id)

        /*char m[BUFFER_SIZE];
        size_t m_len;
        if (!get_sk_fp(filename, &sk)||!ibe_decrypt(p_sec_packet->payload.data, c_len, m, &m_len, &sk))
        {
            ERROR("decrypt fail");
            throw std::exception();
        };*/
        char *m = (char *)malloc(BUFFER_SIZE);
        IBEPrivateKey sk = NULL;
        size_t m_len;
        get_sk_fp(filename, &sk);
        ibe_decrypt(p_sec_packet->payload.data, c_len, m, &m_len, &sk);
        fprintf(stderr, "m is %s\n", m);
        FREE_SK_FILENAME;


        #ifdef DEBUG 
        fprintf(stderr, "message length : %d\n", m_len); 
        fprintf(stderr, "message : %s\n", m);
        #endif

        // make the app packet 
        AppPacket *app_packet = new AppPacket;
        memcpy(app_packet->head, m, APP_HEAD_LEN);       //head中放入解密前8位的内容
        int payload_len = *(int *)(m+4);                // get the length of the payload 

        char *payload = (char *)malloc(payload_len);
        memcpy(payload, m+APP_HEAD_LEN, payload_len);
        app_packet->payload = payload;       //payload中放入解密后8位的内容

        #ifdef DEBUG 
        fprintf(stderr, "payload length : %d\n", payload_len);
        fprintf(stderr, "payload : %s\n", payload);
        #endif

        // add the app packet to the payload of the sec packet 
        p_sec_packet->payload.appPacket = app_packet;

        fprintf(stderr, "fin payload : %s\n",  get_ctx()->payload.secPacket->payload.appPacket->payload);
        break;
    }

    case SM4_TYPE:
    {
        sm4_context sm4ctx;

        #ifdef DEBUG
        for(int t=0;t<16;t++)
            printf("%02x ",sm4key[t]);
        printf("\n");
        #endif
        sm4_setkey_dec(&sm4ctx, sm4key);
        fprintf(stderr, "data is%s\n",p_sec_packet->payload.data);
        int N = strlen(p_sec_packet->payload.data);
        #ifdef DEBUG
        fprintf(stderr, "len is %d\n",N);
        #endif
        unsigned char *sk = (unsigned char *)malloc(IBE_SK_LEN);
	    sm4_crypt_ecb(&sm4ctx, 0, IBE_SK_LEN, (unsigned char*)(p_sec_packet->payload.sk_data),sk);
        #ifdef DEBUG
        fprintf(stderr, "id为：%s\n",ctx->dest_id->id);
		fprintf(stderr, "解密得到sk：%s\n",sk);
        fprintf(stderr, "私钥的长度为：%d\n",strlen(p_sec_packet->payload.data));
        #endif

        GENERATE_SK_FILENAME(ctx->dest_id)        

        #ifdef DEBUG
        fprintf(stderr, "sk_filename is%s\n", filename);
        #endif
        FILE *fp2;
        if((fp2=fopen(filename,"wb+"))==NULL)
        {
            printf("file cannot open \n");  
        }
        fprintf(fp2,"%s",sk);
        fclose(fp2);

        #ifdef DEBUG
        fprintf(stderr,"sk_file generate\n");
        #endif

        FREE_SK_FILENAME;

        *(int *)(p_sec_packet->payload.appPacket->head) = PRIVATE_KEY_RESPONSE_TYPE;

        break;
    }
        
    default:
        break;
    }

    ctx->phase = RECV_VERIFY;
end:
    #ifdef DEBUG 
    fprintf(stderr, "return test\n");
    #endif
}