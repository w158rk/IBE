#include <packet.hpp>

#ifdef DEBUG 
#include <sstream>
#endif

using namespace packet;

int Packet::packet_handle(PacketCTX* ctx) {
    
    // store the current ctx and restore it after send
    PacketCTX *old_ctx = nullptr;
    if(m_fctx){
        old_ctx = m_ctx;
    }
    set_ctx(ctx);
    
    packet_handle();

    if(old_ctx != nullptr) 
    {
        m_ctx = old_ctx;
    }
    else
    {
        m_ctx = nullptr;
        m_fctx = false;
    }

    delete ctx;

#ifdef DEBUG 
    interface::IUI::debug("handle a packet finished");
#endif

    return 1;
}

void Packet::packet_handle()
{
    PacketCTX *ctx = get_ctx();

    while(ctx->get_phase() != RECV_DONE) {
#ifdef DEBUG
    std::ostringstream s;
    s << "handle phase: " << ctx->get_phase() ;
    interface::IUI::debug(s.str());
#endif 

        switch (ctx->get_phase())
        {
        case RECV_APP_PACKET:
            handle_ap();
            break;
        case RECV_VERIFY:
            handle_verify();
            break;
        case RECV_DEC:
            handle_dec();
            break;
        case RECV_SEC_PACKET:
            handle_sp();
            break;
        }
    }

}