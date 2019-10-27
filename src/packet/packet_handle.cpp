#include <packet.hpp>

using namespace packet;

int Packet::packet_handle(PacketCTX* ctx) {
    
    set_ctx(ctx);

    packet_handle();

    return 1;
}

void Packet::packet_handle()
{
    PacketCTX *ctx = get_ctx();

    while(ctx->phase != RECV_DONE) {
        #ifdef DEBUG 
        fprintf(stderr, "handle phase : %d\n", ctx->phase);
        #endif
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
    free_ctx(ctx);
    m_fctx = false;
    m_ctx = nullptr;

}