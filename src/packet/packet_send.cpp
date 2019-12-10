#include <packet.hpp>
#include <ui.hpp>
#include <string.h>

#ifdef DEBUG
#include <sstream>
#endif

using namespace packet;

int Packet::packet_send(PacketCTX* ctx) {
    
    // store the current ctx and restore it after send
    int ret = 0;
    PacketCTX *old_ctx = nullptr;
    if(m_fctx){
        old_ctx = m_ctx;
    }
    set_ctx(ctx);

    try
    {
        packet_send();
    }
    catch(PacketException& e)
    {
        ui::UInterface::error(e.what());
        goto end;
    }
    
    ret = 1;

end:

    if(old_ctx != nullptr) 
    {
        m_ctx = old_ctx;
    }
    else
    {
        set_ctx(nullptr);
        m_fctx = false;
    }

    delete ctx->get_payload_sec();
    delete ctx;
    return ret;

}

void Packet::packet_send() 
{
    PacketCTX *ctx = get_ctx();

    while(ctx->get_phase() != SEND_DONE) {

#ifdef DEBUG
    std::ostringstream s;
    s << "send phase: " << ctx->get_phase() ;
    interface::IUI::debug(s.str());
#endif 

        switch (ctx->get_phase())
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
	SecPacket *p_sec_packet = ctx->get_payload_sec();

    int len = p_sec_packet->get_length();

    // send the head and payload, together
    char *data = p_sec_packet->to_bytes();

    // send the packet from the comm object
    int length = get_comm_ptr()->send(data, len+SEC_HEAD_LEN+IBE_SIGN_LEN);
    std::free(data);

    if (length != len + SEC_HEAD_LEN+IBE_SIGN_LEN) {
        throw PacketException("error in write file");
    }

}