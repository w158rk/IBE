/**
 * @file send_ap.c
 * @author Wang Ruikai 
 * @date August 9th, 2019 
 * @brief send the packet in the App Packet level
 */

#include<packet.h>
#include <string.h>
// #define DEBUG

int send_ap(PacketCTX *ctx)
{
    int rtn = 0;

    if(ctx->phase != SEND_APP_PACKET) {
        ERROR("call wrong function");
        goto end;
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
        case SESSION_KEY_ACK_TYPE:
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
    send_packet->payload.appPacket = packet;
    ctx->payload.secPacket = send_packet;
    //fprintf(stderr,"sk: %s\n",ctx->payload.secPacket->payload.appPacket->payload);
    ctx->phase = SEND_SIGN;

    rtn = 1;

end:
    if(rtn==0) {
        free(send_packet);
    }
    return rtn;
}