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
    //fprintf(stderr,"sk1 is :%s\n",ctx->payload.secPacket->payload.appPacket->payload);
    //fprintf(stderr,"sk2 is :%s\n",sec_packet->payload.appPacket->payload);
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
            printf("here is SM4_TYPE");
            #endif
            
            /*iv = cbc_iv_new();
            if (!gen_random_iv(iv) ||
                !cbc_encrypt(data, (size_t)length+APP_HEAD_LEN, 
                        ctx->sm4_key, iv, cipher, &cipher_len)) 
            {
                ERROR("encrypt failed");
                goto end;
            }*/
            int length = IBE_SK_LEN;
            char *sk_data = (char *)malloc(length);
            memcpy(sk_data, ctx->payload.secPacket->payload.appPacket->head, APP_HEAD_LEN);
            memcpy(sk_data, ctx->payload.secPacket->payload.appPacket->payload, IBE_SK_LEN);
            #ifdef DEBUG
            fprintf(stderr, "sk is:%s\n", sk_data);
            fprintf(stderr, "sm4_key is:%s\n", ctx->sm4_key);
            #endif
            sm4_context sm4ctx;
            sm4_setkey_enc(&sm4ctx,ctx->sm4_key);
            sm4_crypt_ecb(&sm4ctx,1,length,sk_data,cipher);
            #ifdef DEBUG
            fprintf(stderr, "cipher is:%s\n",cipher);
            #endif
            #ifdef DEBUG
            fprintf(stderr, "[%s:%d] cipher length is:%d\n", __FILE__, __LINE__, length);
            #endif
            
            sec_packet->payload.data = (char *)malloc(length);
            memcpy(sec_packet->payload.data, cipher, length);
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