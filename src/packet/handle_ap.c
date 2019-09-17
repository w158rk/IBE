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
// #define DEBUG

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
    #ifdef DEBUG 
    fprintf(stderr, "[%s : %d] payload : %s\n", __FILE__, __LINE__, packet->payload);
    #endif
    char *head = packet->head;
    unsigned char *payload = packet->payload;        //获取的payload为client的SM4_key加上id

    /* It may cause some problem for not using the network order */
    //int payload_len = *(int *)(head + 4);
    int payload_len = strlen(payload);
    #ifdef DEBUG 
    fprintf(stderr, "payload: %x-\n", payload);
    fprintf(stderr, "payload_len: %d\n", payload_len);
    #endif
    int id_len = strlen(payload+SM4_KEY_LEN);       //计算id的长度

    IBEMasterSecret msk = NULL;
    IBEPrivateKey sk = NULL;

    if (get_msk_fp(MSK_FILENAME, &msk) == 0) {
        ERROR(" you don't have the access to msk file");
        goto end;
    }       //从文件中读取s

    // there is a but that sucks 
    // it seems that the function get_msk_fp would change the value of packet->payload 
    // i don't know why, may be some magic things

    #ifdef DEBUG 
    fprintf(stderr, "id_len is: %d\n", id_len);
    fprintf("[%s : %d] extract finished\n", __FILE__, __LINE__);
    fprintf(stderr, "&msk : %ld \n", msk);
    fprintf(stderr, "id: %s", payload + SM4_KEY_LEN);
    fprintf(stderr, "payload1: %x\n", payload);
    #endif

    /*生成私钥sk*/
    if ( 0 == ibe_extract(&sk, &msk, payload+SM4_KEY_LEN, (size_t)id_len)) {
        ERROR(" cannot extract the private key");
        goto end;
    }       

    #ifdef DEBUG 
    fprintf(stderr, "[%s : %d] extract finished\n", __FILE__, __LINE__);
    #endif
    // TODO 
    // finish extracting the requested private key 
    // the next step is to send the key to the client 
    // the following code is not checked

    PacketCTX send_ctx;
    AppPacket send_packet;

    *(int *)(send_packet.head) = PRIVATE_KEY_RESPONSE_TYPE;
    *(int *)(send_packet.head+4) = IBE_SK_LEN;      //头部存放了标示和私钥长度
    char *p = (char *)malloc(IBE_SK_LEN);
    memcpy(p, sk, IBE_SK_LEN);
    send_packet.payload = p;        //payload中存放私钥
    send_ctx.phase = SEND_APP_PACKET;
    send_ctx.payload.appPacket = &send_packet;
     #ifdef DEBUG 
    fprintf(stderr, "payload2: %x\n", payload);
    #endif
    //char ch[16];
    strncpy(send_ctx.sm4_key, payload, 16);
    //send_ctx.sm4_key = ch;

    #ifdef DEBUG
    fprintf(stderr, "payload3: %s\n", payload);
    fprintf(stderr, "send_ctx.sm4_key): %s\n", send_ctx.sm4_key);
    //fprintf(stderr, "sm4_key: %x\n", send_ctx.sm4_key);
    #endif

    if(0 == packet_send(&send_ctx)) {
        ERROR("send the packet error");
        goto end;
    }

    rtn = 1;

end:
    free(sk);
    free(msk);
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

    #ifdef DEBUG 
    fprintf(stderr, "[%s : %d]type : %d\n", __FILE__, __LINE__, type);
    #endif

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