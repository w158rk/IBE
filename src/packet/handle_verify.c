#include <packet.h>

int handle_verify(PacketCTX *ctx) {
    ctx->phase = RECV_APP_PACKET;
    ctx->payload.appPacket = ctx->payload.secPacket->payload.appPacket;
    return 1;
}