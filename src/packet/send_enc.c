/**
 * @file send_enc.c
 * @author Wang Ruikai 
 * @date August 9th, 2019 
 * @brief encrypt the app_packet
 */

#include<packet.h>
#include <crypto.h>
#include <string.h>

int send_enc(PacketCTX *ctx)
{
    int rtn = 0;

    if(ctx->phase != SEND_ENC) {

        ERROR("call wrong function");
        goto end;
    }

    SecPacket *sec_packet = ctx->payload.secPacket;
    AppPacket *app_packet = sec_packet->payload.appPacket;
    int length = *(int *)(app_packet->head+4);

    #ifdef DEBUG 
    fprintf(stderr, "packet length : %d\n", length);
    #endif

    char *data = (char *)malloc(length + APP_HEAD_LEN);
    memcpy(data, app_packet->head, APP_HEAD_LEN);
    memcpy(data+APP_HEAD_LEN, app_packet->payload, length);

    int type = *(int *)(sec_packet->head);
    char *cipher = (char *)malloc(BUFFER_SIZE);
    size_t cipher_len = BUFFER_SIZE;
    char *iv = NULL;

    switch (type)
    {
    case IBE_TYPE:
        #ifdef DEBUG 
        fprintf(stderr, "[%s:%d] IBE ENC\n", __FILE__, __LINE__);
        #endif

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
        break;
    
    case AES_TYPE:
        
        iv = cbc_iv_new();
        if (!gen_random_iv(iv) ||
            !cbc_encrypt(data, (size_t)length+APP_HEAD_LEN, 
                    ctx->aes_key, iv, cipher, &cipher_len)) 
        {
            ERROR("encrypt failed");
            goto end;
        }
        break;
    
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