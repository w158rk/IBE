#include <packet.hpp>

using namespace packet;

void Packet::handle_verify() {
    PacketCTX *ctx = get_ctx();
    ctx->set_phase(RECV_APP_PACKET);

    delete ctx->get_payload_sec();

    ctx->set_payload_app(ctx->get_payload_sec()->get_payload_app());
}