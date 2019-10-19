/**
 * @file send_sp.c
 * @author Wang Ruikai 
 * @date August 9th, 2019 
 * @brief convert the sec packet into char array
 */

#include<packet.hpp>

using namespace packet;

void Packet::send_sp()
{

    PacketCTX *ctx = get_ctx();
    if(ctx->phase != SEND_SEC_PACKET) {

        ERROR("call wrong function");
    }
    ctx->phase = SEND_DONE;
}