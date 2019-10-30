#include <packet.hpp>

#define DEBUG
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

    free_ctx(ctx);
    return 1;
}

void Packet::packet_handle()
{
    PacketCTX *ctx = get_ctx();

    while(ctx->phase != RECV_DONE) {
        switch (ctx->phase)
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

    /** When the handle of the packet is finished, 
     * the context should be freed and 
     * the member ctx should be null 
     * f_ctx should be false 
     */

}