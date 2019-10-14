/**
 * @file send_enc.c
 * @author Wang Ruikai 
 * @date August 9th, 2019 
 * @brief encrypt the app_packet
 */

#include<packet.h>
#include<openssl/sm4.h>
#include <crypto.h>
#include <string.h>
//#define DEBUG

int send_enc(PacketCTX *ctx)
{
    int rtn = 0;

    if(ctx->phase != SEND_ENC) {

        ERROR("call wrong function");
        goto end;
    }

    SecPacket *sec_packet = ctx->payload.secPacket;
    #ifdef DEBUD
    fprintf(stderr,"sk1 is :%s\n",ctx->payload.secPacket->payload.appPacket->payload);
    #endif
    AppPacket *app_packet = sec_packet->payload.appPacket;
    int length = *(int *)(app_packet->head+4);

    #ifdef DEBUG 
    fprintf(stderr, "packet length : %d\n", length);
    #endif

    char *data = (char *)malloc(length + APP_HEAD_LEN);
    memcpy(data, app_packet->head, APP_HEAD_LEN);
    memcpy(data+APP_HEAD_LEN, app_packet->payload, length); 

    int type = *(int *)(sec_packet->head);
    //unsigned char cipher[100000];
    char *cipher = (char *)malloc(BUFFER_SIZE);
    size_t cipher_len = BUFFER_SIZE;

    switch (type)
    {
        case IBE_TYPE:
        {
            #ifdef DEBUG 
            fprintf(stderr, "[%s:%d] IBE ENC\n", __FILE__, __LINE__);
            #endif
            //IBE
            if (!ibe_encrypt(data, (size_t)length+APP_HEAD_LEN, 
                        cipher, &cipher_len, 
                        ctx->mpk, ctx->dest_id, ctx->dest_id_len))
            {
                ERROR("encrypt failed");
                goto end;
            }

            #ifdef DEBUG 
            fprintf(stderr, "[%s:%d] type : %d\n", __FILE__, __LINE__, type);
            #endif

            sec_packet->payload.data = (char *)malloc(cipher_len);
            memcpy(sec_packet->payload.data, cipher, cipher_len);
                
            // length without header 
            *(int *)(sec_packet->head+4) = (int)cipher_len;
            //fprintf(stderr,"sk is :%s\n",ctx->payload.secPacket->payload.appPacket->payload);
            break;
        }
    
        case SM4_TYPE:
        {
            int length_sk = strlen(sec_packet->payload.appPacket->payload);

            char *sk_data = (char *)malloc(IBE_SK_LEN);
            #ifdef DEBUG
            fprintf(stderr, "sk is: %s\n", sec_packet->payload.appPacket->payload);
            #endif
            memcpy(sk_data, sec_packet->payload.appPacket->payload, IBE_SK_LEN);

            char *output = (char *)malloc(BUFFER_SIZE);
            sm4_context sm4ctx;
            unsigned char *key = (unsigned char *)malloc(16);

            #ifdef DEBUG
            for(int t=0;t<16;t++)
                printf("%02x ",ctx->key[t]);
            printf("\n");
            #endif
            
            sm4_setkey_enc(&sm4ctx,ctx->key);
            sm4_crypt_ecb(&sm4ctx, 1, IBE_SK_LEN, sk_data, cipher);
             #ifdef DEBUG
             fprintf(stderr, "sk_length is:%d\n", length_sk);
            fprintf(stderr, "cipher is:%s\n",cipher);
            sm4_setkey_dec(&sm4ctx, ctx->key);
            sm4_crypt_ecb(&sm4ctx,0,IBE_SK_LEN,cipher, output);
            fprintf(stderr, "output is:%s\n", output);
            int out_len = strlen(output);
            fprintf(stderr, "out_len is %d\n", out_len);
            #endif
            //SecPacket *send_sec;
            sec_packet->payload.data = (char *)malloc(BUFFER_SIZE);
            memcpy(sec_packet->payload.data, cipher, BUFFER_SIZE);
            *(int *)(sec_packet->payload.appPacket->head) = PRIVATE_KEY_RESPONSE_TYPE;
            
            #ifdef DEBUG
            fprintf(stderr, "the last sk is :%s\n", ctx->payload.secPacket->payload.data);
            #endif


            break;
        }
        
    
    default:
        break;
    }

    ctx->phase = SEND_SEC_PACKET;
    rtn = 1;
end:
    free(data);
    free(cipher);
    return rtn;
}