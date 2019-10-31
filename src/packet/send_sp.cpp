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
    if(ctx->get_phase() != SEND_SEC_PACKET) {
        interface::IUI::error("call wrong function send_sp");
        throw PacketException("call wrong function send_sp");        
    }
    ctx->set_phase(SEND_DONE);
}