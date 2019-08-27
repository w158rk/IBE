#include <packet.h>

int handle_sp(PacketCTX *ctx) {

    ctx->phase = RECV_DEC;

    return 1;
}