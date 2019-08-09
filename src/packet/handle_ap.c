/**
 * @file handle_ap.c 
 * @author Wang Ruikai 
 * @date August 8th, 2019 
 * @brief handle the packet in the App Packet phase
 */

#include <packet.h>
#include <crypto.h>
#include <sys.h>
#include <string.h>

int handle_m(PacketCTX *ctx)
{
    int rtn = 0;

    AppPacket *packet = ctx->payload.appPacket;
    char *head = packet->head;
    int length = *(int *)(head + 4);
    
    /*@todo forbid the overflow, but it may cause some other problem */
    packet->payload[length] = '\0';     

    printf("receive message : %s\n", packet->payload);
    rtn = 1;

end:

    return rtn;
}


int handle_sk_request(PacketCTX *ctx) {

    int rtn = 0;

    AppPacket *packet = ctx->payload.appPacket;
    char *head = packet->head;
    
    /* It may cause some problem for not using the network order */
    int id_len = *(int *)(head + 4);  
    IBEPrivateKey *sk = NULL;
    IBEMasterSecret *msk = NULL;
    if (get_msk_fp(MSK_FILE, msk) == 0) {
        ERROR(" you don't have the access to msk file");
        goto end;
    }
    if ( 0 ==ibe_extract(sk, msk, packet->payload, (size_t)id_len)) {
        ERROR(" cannot extract the private key");
        goto end;
    }

    PacketCTX send_ctx;
    AppPacket send_packet;

    *(int *)(send_packet.head) = PRIVATE_KEY_RESPONSE_TYPE;
    *(int *)(send_packet.head+4) = IBE_SK_LEN;

    char *p = (char *)malloc(IBE_SK_LEN);
    memcpy(p, *sk, IBE_SK_LEN);
    send_packet.payload = p;

    send_ctx.phase = SEND_APP_PACKET;
    send_ctx.payload.appPacket = &send_packet;

    if(0 == send(send_ctx)) {
        ERROR("send the packet error");
        goto end;
    }

    rtn = 1;

end:
    free(*sk);
    free(*msk);
    return rtn;

}


int handle_sk_response(PacketCTX *ctx) {

    int rtn = 0;
    AppPacket *packet = ctx->payload.appPacket;
    char *head = packet->head;

    int length = *(int *)(head+4);
    if(length != IBE_SK_LEN) {
        ERROR("the length of the private key is wrong");
        goto end;
    }

    int i;
    printf("your private key is (please store it if necessary) : ");
    for(i=0; i<length; i++) {
        if(i%4==0) printf(" ");
        if(i%16==0) printf("\n");
        printf("%02x", packet->payload[i] & 0xff);
    }
    printf("\n");

    rtn = 1;

end:
    return rtn;

}


int handle_session_request(PacketCTX *ctx) {
    
}


int handle_session_ack(PacketCTX *ctx) {

}


int handle_session_final(PacketCTX *ctx) {

}


int handle_ap(PacketCTX *ctx) {

    int rtn = 0;

    if(ctx->phase != RECV_APP_PACKET) {
        ERROR("call wrong function");
        goto end;
    }

    AppPacket *packet = ctx->payload.appPacket;
    char *head = packet->head;

    /* analyze the head */
    int type = *(int *)head;

    switch (type)
    {
    case PLAIN_MESSAGE_TYPE:
        handle_m(ctx);
        break;
    
    case PRIVATE_KEY_REQUEST_TYPE:
        handle_sk_request(ctx);
        break;
    
    case PRIVATE_KEY_RESPONSE_TYPE:
        handle_sk_response(ctx);
        break;
    
    case SESSION_KEY_REQUEST_TYPE:
        handle_session_request(ctx);
        break;

    case SESSION_KEY_ACK_TYPE:
        handle_session_ack(ctx);
        break;

    case SESSION_KEY_FINAL_TYPE:
        handle_session_final(ctx);
        break;
    
    default:
        ERROR("the packet type is invalid");
        goto end;
        break;
    }

    ctx->phase = SEND_DONE;
    rtn = 1;

end:
    return rtn;
}