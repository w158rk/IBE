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

#define DEBUG
#ifdef DEBUG 
#include<iostream>
#endif

using namespace packet;


void Packet::send_enc()
{
    // at this phase, there is a sec packet in the 
    // ctx object, so the app packet is in the payload 
    // of that sec packet
    PacketCTX *ctx = get_ctx();

    if(ctx->phase != SEND_ENC) {
        throw PacketException("call wrong function");
    }

    SecPacket *sec_packet = ctx->payload.secPacket;
    AppPacket *app_packet = sec_packet->payload.appPacket;
    int app_length = *(int *)(app_packet->head+4);

    int sec_type = *(int *)(sec_packet->head);

    switch (sec_type)
    {
        case IBE_TYPE:
        {
            char *cipher = (char *)std::malloc(BUFFER_SIZE);
            size_t cipher_len = BUFFER_SIZE;
            char *data = (char *)malloc(app_length + APP_HEAD_LEN);
            
            /**copy the header and payload of the app packet into 
             * the data for encryption
             */
            memcpy(data, app_packet->head, APP_HEAD_LEN); 
            memcpy(data+APP_HEAD_LEN, app_packet->payload, app_length); 

#ifdef DEBUG 
            fprintf(stderr, "[%s:%d] IBE ENC\n", __FILE__, __LINE__);
            fprintf(stderr, "dest id is:%s\n", ctx->dest_id->id);
#endif  

            // encrypt
            if (!ibe_encrypt(data, (size_t)app_length+APP_HEAD_LEN, 
                        cipher, &cipher_len, 
                        &(ctx->mpk), ctx->dest_id->id, ctx->dest_id->length))
            {
                throw PacketException("encrypt failed");
            }

#ifdef DEBUG 
            std::cerr << "encrypted length: " << cipher_len << std::endl;
#endif

            // copy the cipher into the sec packet
            sec_packet->payload.data = (char *)malloc(cipher_len);
            memcpy(sec_packet->payload.data, cipher, cipher_len);       //将加密后的数据放到sec_packet的payload.data中

            // length without header 
            *(int *)(sec_packet->head+4) = (int)cipher_len;     //sec_packet的head后4位存放密文的长度
            
            // free the temporaries
            std::free(data);
            std::free(cipher);

            break;
        }
    
        case SM4_TYPE:
        {   
#ifdef DEBUG
            fprintf(stderr, "sk is: %s\n", sec_packet->payload.appPacket->payload);
            fprintf(stderr, "app packet length before sm4 encryption is: %d\n", app_length);
#endif
            
            // allocate space for plain data and cipher
            char *sk_data = (char *)std::malloc(app_length + APP_HEAD_LEN);
            char *cipher = (char *)std::malloc(BUFFER_SIZE);

            // copy the app packet into the plain data field
            memcpy(sk_data, app_packet->head, APP_HEAD_LEN);
            memcpy(sk_data + APP_HEAD_LEN, app_packet->payload, app_length);
            //size_t cipher_len = BUFFER_SIZE;

#ifdef DEBUG
            char *output = (char *)malloc(BUFFER_SIZE);
#endif

            int len = app_length + APP_HEAD_LEN;
            int c_len;
            // encrypt
            sm4_context *sm4ctx = new sm4_context;
            sm4_setkey_enc(sm4ctx,(unsigned char*)(ctx->key));

            // TODO : 1 here should be a readable macro
            sm4_crypt_ecb(sm4ctx, ENC_PARAMETER, app_length + APP_HEAD_LEN, (unsigned char*)sk_data, (unsigned char*)cipher, &c_len);
#ifdef DEBUG
            fprintf(stderr, "c_len is%d\n", c_len);
#endif
                 
#ifdef DEBUG
            fprintf(stderr, "cipher is:%s\n",cipher);
            /*对生成的cipher进行验证是否正确*/
            sm4_setkey_dec(sm4ctx, (unsigned char*)(ctx->key));
            unsigned char *data = (unsigned char *)std::malloc(c_len);
            memcpy(data, cipher, c_len);
            int out_len;
            sm4_crypt_ecb(sm4ctx,DEC_PARAMETER,c_len,(unsigned char*)data, (unsigned char*)output, &out_len);
            fprintf(stderr, "output sk is:%s\n", output + APP_HEAD_LEN);
#endif

            /**
             * TODO : calculate the cipher length from somewhere
             * here the segmentation fault is likely to happen
             */
            sec_packet->payload.data = (char *)malloc(c_len);
            memcpy(sec_packet->payload.data, cipher, c_len);       //加密后的信息放在sec_packet下的payload.sk_data中
            
            *(int *)(sec_packet->head+4) = (int)c_len;     //sec_packet的head后4位存放密文的长度

            break;
        }
        
    
    default:
        break;
    }

    ctx->phase = SEND_SEC_PACKET;
}