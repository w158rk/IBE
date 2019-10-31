#include <packet.hpp>

using namespace packet;

void Packet::handle_sp() {

    PacketCTX *ctx = get_ctx();
    ctx->set_phase(RECV_DEC);

}