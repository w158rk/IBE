/**
 * @file send_s.c
 * @author Wang Ruikai 
 * @date August 9th, 2019 
 * @brief add signature to the sec packet
 */

#include<packet.hpp>

using namespace packet;

void Packet::send_sign()
{
    PacketCTX *ctx = get_ctx();
    ctx->set_phase (SEND_ENC);

}