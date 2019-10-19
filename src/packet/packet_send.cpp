#include <packet.hpp>
#ifdef DEBUG
#include <stdio.h>
#endif

using namespace packet;

int Packet::packet_send(PacketCTX* ctx) {

    set_ctx(ctx);
    packet_send();
    return 1;

}

void Packet::packet_send() 
{
    PacketCTX *ctx = get_ctx();

    while(ctx->phase != SEND_DONE) {
        #ifdef DEBUG 
        fprintf(stderr, "phase : %d\n", ctx->phase);
        #endif
        switch (ctx->phase)
        {
        case SEND_APP_PACKET:
            send_ap();
            break;
        case SEND_SIGN:
            send_sign();
            break;
        case SEND_ENC:
            send_enc();
            break;
        case SEND_SEC_PACKET:
            send_sp();
            break;
        }
    }
    // 1. send the head 
	SecPacket *sec_packet = ctx->payload.secPacket;

    #ifdef DEBUG
    fprintf(stderr,"%x\n", sec_packet->head);
    #endif

    int length = get_comm_ptr()->send(sec_packet->head, SEC_HEAD_LEN);
    if (length != SEC_HEAD_LEN) {
        fprintf(stderr,"error in write file");
        throw std::exception();
    }
    
	// 2. send the payload
	int len = *(int *)(sec_packet->head+4);
    length = get_comm_ptr()->send(sec_packet->payload.data, len);
    if (length != len) {
        fprintf(stderr,"error in write file");
        throw std::exception();
    }

}