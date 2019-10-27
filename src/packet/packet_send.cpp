#include <packet.hpp>
#ifdef DEBUG
#include <stdio.h>
#endif

using namespace packet;

int Packet::packet_send(PacketCTX* ctx) {
    
    // store the current ctx and restore it after send
    PacketCTX *old_ctx = nullptr;
    if(m_fctx){
        old_ctx = m_ctx;
    }
    set_ctx(ctx);
    packet_send();

    if(old_ctx != nullptr) 
    {
        m_ctx = old_ctx;
    }
    else
    {
        set_ctx(nullptr);
        m_fctx = false;
    }

    free_ctx(ctx);
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
    fprintf(stderr,"the first word of the sec head : %d\n", *(int *)(sec_packet->head));
    #endif

    int length = get_comm_ptr()->send(sec_packet->head, SEC_HEAD_LEN);
    if (length != SEC_HEAD_LEN) {
        fprintf(stderr,"[%s:%d] error in write file\n", __FILE__, __LINE__);
        throw std::exception();
    }
    
	// 2. send the payload
	int len = *(int *)(sec_packet->head+4);
    #ifdef DEBUG
    fprintf(stderr,"[%s:%d] the length of the sec packet : %d\n", __FILE__, __LINE__, len);
    #endif
    length = get_comm_ptr()->send(sec_packet->payload.data, len);

    #ifdef DEBUG
    fprintf(stderr,"[%s:%d] mark \n", __FILE__, __LINE__);
    #endif

    if (length != len) {
        fprintf(stderr,"[%s:%d] error in write file\n", __FILE__, __LINE__);
        throw std::exception();
    }

}