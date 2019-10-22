/**
 * @file send_enc.c
 * @author Wang Ruikai 
 * @date August 9th, 2019 
 * @brief encrypt the app_packet
 */

extern "C" {
    #include <crypto.h>
    #include <string.h>
}

#include<packet.hpp>
#include<config.h>
using namespace packet;
//#define DEBUG

void Packet::send_enc()
{
    PacketCTX *ctx = get_ctx();

    if(ctx->phase != SEND_ENC) {
        ERROR("call wrong function");
        throw std::exception();
    }

    SecPacket *sec_packet = ctx->payload.secPacket;
    AppPacket *app_packet = sec_packet->payload.appPacket;
    int length = *(int *)(app_packet->head+4);

    #ifdef DEBUG 
    fprintf(stderr, "app packet length : %d\n", length);
    #endif    

    int type = *(int *)(sec_packet->head);
    #ifdef DEBUG 
    fprintf(stderr, "[%s:%d] type : %d\n", __FILE__, __LINE__, type);
    #endif  

    char *cipher = (char *)malloc(BUFFER_SIZE);
     size_t cipher_len = BUFFER_SIZE;

    switch (type)
    {
        case IBE_TYPE:
        {
            char *data = (char *)malloc(length + APP_HEAD_LEN);
            /*data中存放head和payload的信息*/
            memcpy(data, app_packet->head, APP_HEAD_LEN); 
            memcpy(data+APP_HEAD_LEN, app_packet->payload, length); 
            #ifdef DEBUG 
            fprintf(stderr, "[%s:%d] IBE ENC\n", __FILE__, __LINE__);
            fprintf(stderr, "dest id is:%s\n", ctx->dest_id->id);
            #endif  
            //IBE
            if (!ibe_encrypt(data, (size_t)length+APP_HEAD_LEN, 
                        cipher, &cipher_len, 
                        ctx->mpk, ctx->dest_id->id, ctx->dest_id->length))
            {
                ERROR("encrypt failed");
                throw std::exception();
            }

            sec_packet->payload.data = (char *)malloc(cipher_len);
            memcpy(sec_packet->payload.data, cipher, cipher_len);       //将加密后的数据放到sec_packet的payload.data中
                
            // length without header 
            *(int *)(sec_packet->head+4) = (int)cipher_len;     //sec_packet的head后4位存放密文的长度
            break;
        }
    
        case SM4_TYPE:
        {
            #ifdef DEBUG
            fprintf(stderr, "sk is: %s\n", sec_packet->payload.appPacket->payload);
            #endif
            AppPacket packet;
            *(int *)(packet.head) = PRIVATE_KEY_RESPONSE_TYPE;	
            /*sk_data前几位放标示位，APP_HEAD_LEN后存放sk*/
            char *sk_data = (char *)malloc(IBE_SK_LEN + APP_HEAD_LEN);
            memcpy(sk_data, packet.head, APP_HEAD_LEN);
            memcpy(sk_data + APP_HEAD_LEN, sec_packet->payload.appPacket->payload, IBE_SK_LEN);

            char *output = (char *)malloc(BUFFER_SIZE);
            sm4_context sm4ctx;
            unsigned char *key = (unsigned char *)malloc(16);

            #ifdef DEBUG
            for(int t=0;t<16;t++)
                printf("%02x ",ctx->key[t]);
            printf("\n");
            #endif
            
            sm4_setkey_enc(&sm4ctx,(unsigned char*)(ctx->key));
            sm4_crypt_ecb(&sm4ctx, 1, IBE_SK_LEN + APP_HEAD_LEN, (unsigned char*)sk_data, (unsigned char*)cipher);
            
            #ifdef DEBUG
            fprintf(stderr, "cipher is:%s\n",cipher);
            /*对生成的cipher进行验证是否正确*/
            sm4_setkey_dec(&sm4ctx, (unsigned char*)(ctx->key));
            sm4_crypt_ecb(&sm4ctx,0,IBE_SK_LEN + APP_HEAD_LEN,(unsigned char*)cipher, (unsigned char*)output);
            fprintf(stderr, "output sk is:%s\n", output + APP_HEAD_LEN);
            #endif

            sec_packet->payload.sk_data = (char *)malloc(BUFFER_SIZE);
            memcpy(sec_packet->payload.sk_data, cipher, BUFFER_SIZE);       //加密后的信息放在sec_packet下的payload.sk_data中

            break;
        }
        
    
    default:
        break;
    }

    ctx->phase = SEND_SEC_PACKET;
}