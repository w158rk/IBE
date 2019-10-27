#include <packet.hpp>

using namespace packet;

void Packet::handle_verify() {
    PacketCTX *ctx = get_ctx();
    ctx->phase = RECV_APP_PACKET;
    ctx->payload.appPacket = ctx->payload.secPacket->payload.appPacket;     //将ctx->payload中的appPacket信息放到secPacket的payload中
}