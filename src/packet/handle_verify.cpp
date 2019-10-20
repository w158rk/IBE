#include <packet.hpp>

using namespace packet;

void Packet::handle_verify() {
    PacketCTX *ctx = get_ctx();
    //fprintf(stderr, "payload is %s\n", ctx->payload.secPacket->payload.appPacket->payload);
    ctx->phase = RECV_APP_PACKET;
    ctx->payload.appPacket = ctx->payload.secPacket->payload.appPacket;
    //fprintf(stderr, "payload is %s\n", ctx->payload.appPacket->payload);
}