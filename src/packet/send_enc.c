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
#define DEBUG

int send_enc(PacketCTX *ctx)
{
    int rtn = 0;

    if(ctx->phase != SEND_ENC) {

        ERROR("call wrong function");
        goto end;
    }

    SecPacket *sec_packet = ctx->payload.secPacket;
    fprintf(stderr,"sk1 is :%s\n",ctx->payload.secPacket->payload.appPacket->payload);
    fprintf(stderr,"sk2 is :%s\n",ctx->payload.appPacket->payload);
    AppPacket *app_packet = sec_packet->payload.appPacket;
    int length = *(int *)(app_packet->head+4);

    #ifdef DEBUG 
    fprintf(stderr, "packet length : %d\n", length);
    #endif

    char *data = (char *)malloc(length + APP_HEAD_LEN);
    memcpy(data, app_packet->head, APP_HEAD_LEN);
    memcpy(data+APP_HEAD_LEN, app_packet->payload, length);     //data为haed+payload的内容

    int type = *(int *)(sec_packet->head);
    char *cipher = (char *)malloc(BUFFER_SIZE);
    size_t cipher_len = BUFFER_SIZE;

    switch (type)
    {
        case IBE_TYPE:
        {
            #ifdef DEBUG 
            fprintf(stderr, "[%s:%d] IBE ENC\n", __FILE__, __LINE__);
            #endif
            //IBE??
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
            #ifdef DEBUG
            printf("here is SM4_TYPE\n");
            #endif
            //fprintf(stderr, "sm4_key is %s\n", ctx->sm4_key);

            int length_sk = strlen(sec_packet->payload.appPacket->payload);
            int length_ci;
            int out_len = 0;

            char *sk_data = (char *)malloc(IBE_SK_LEN);
            fprintf(stderr, "sk is: %s\n", sec_packet->payload.appPacket->payload);
            memcpy(sk_data, sec_packet->payload.appPacket->payload, IBE_SK_LEN);
            #ifdef DEBUG
            fprintf(stderr, "sk is:%s\n", sk_data);
            fprintf(stderr, "sm4_key is %s\n", ctx->key);
            for(int t=0;t<16;t++)
                printf("%02x ",ctx->key[t]);
            printf("\n");
            #endif
        

            char *output = (char *)malloc(BUFFER_SIZE);
            sm4_context sm4ctx;
            sm4_setkey_enc(&sm4ctx,ctx->key);
            //int length_sk = strlen(sk_data);
            sm4_crypt_ecb(&sm4ctx,1,length_sk, sk_data,cipher);
            #ifdef DEBUG
            fprintf(stderr, "sk is:%s\n", sk_data);
            fprintf(stderr, "sk_length is:%d   \n", length_sk);
            fprintf(stderr, "cipher is:%s\n",cipher);
            #endif

            
            sm4_setkey_dec(&sm4ctx, ctx->key);
            length_ci = strlen(cipher);
            fprintf(stderr, "cipher length is%d\n", length_ci);
            sm4_crypt_ecb(&sm4ctx,0,length_ci,cipher, output);
            fprintf(stderr, "output is:%s\n", output);
            out_len = strlen(output);
            fprintf(stderr, "out_len is %d\n", out_len);
             
            sec_packet->payload.data = (char *)malloc(length_ci);
            memcpy(sec_packet->payload.data, cipher, length_ci);
            #ifdef DEBUG
            fprintf(stderr, "the last sk is :%s\n", ctx->payload.secPacket->payload.data);
            #endif

            break;
        }
        
    
    default:
        break;
    }
    //fprintf(stderr,"sk is :%s\n",ctx->payload.secPacket->payload.appPacket->payload);

    ctx->phase = SEND_SEC_PACKET;
    rtn = 1;
end:
    free(data);
    free(cipher);
    return rtn;
}