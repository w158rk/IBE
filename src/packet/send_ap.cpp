/**
 * @file send_ap.c
 * @author Wang Ruikai 
 * @date August 9th, 2019 
 * @brief send the packet in the App Packet level
 */


extern "C" {
#include <string.h>
}
//#define DEBUG
#include<config.h>
#include<packet.hpp>
using namespace packet;

void Packet::send_ap()
{
    PacketCTX *ctx = get_ctx();

    if(ctx->phase != SEND_APP_PACKET) {
        ERROR("call wrong function");
        throw std::exception();
    }

    AppPacket *packet = ctx->payload.appPacket;
    char *head = packet->head;
    int send_type, type = *(int *)head;

    switch (type)
    {
        case PLAIN_MESSAGE_TYPE:
        case PRIVATE_KEY_RESPONSE_TYPE:
        case SESSION_KEY_FINAL_TYPE:
            send_type = SM4_TYPE;
            break;
        
        case PRIVATE_KEY_REQUEST_TYPE:
        {
            memcpy(sm4key, ctx->payload.appPacket->payload, 16);
            #ifdef DEBUG
            for(int t=0;t<16;t++)
                printf("%02x ",sm4key[t]);
            printf("\n");
            #endif
        }
        case SESSION_KEY_ACK_TYPE:
            send_type = IBE_TYPE;
            break;
        case IBE_MES_TYPE:
            send_type = IBE_TYPE;
            break;

        default:
            send_type = NO_ENC_TYPE;
    }

    #ifdef DEBUG 
    fprintf(stderr, "send type : %d\n", send_type);
    #endif
    //生成send_packet
    SecPacket *send_packet = (SecPacket *)malloc(sizeof(SecPacket));  
    
    *(int *)(send_packet->head) = send_type;
    fprintf(stderr, "send type is:%d\n", send_type);
    send_packet->payload.appPacket = packet;
    #ifdef DEBUG
    fprintf(stderr, "sk1 is: %s\n", send_packet->payload.appPacket->payload);
    #endif
    ctx->payload.secPacket = send_packet;
    #ifdef DEBUG
    fprintf(stderr, "sk2 is: %s\n", ctx->payload.secPacket->payload.appPacket->payload);
    #endif
    ctx->phase = SEND_SIGN;

}