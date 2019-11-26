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

    if(ctx->get_phase() != SEND_SIGN) {
        interface::IUI::error("call wrong function");
        throw PacketException("call wrong function");
    }

    SecPacket *p_sec_packet = ctx->get_payload_sec();
    int sec_type = p_sec_packet->get_type();

    AppPacket *p_app_packet = p_sec_packet->get_payload_app();
    int app_length = p_app_packet->get_length();

    /*获取自己的sign*/
    SignMesg *sign = NULL;
    
    p_app_packet->set_sign(sign);
    p_sec_packet->set_payload_app(p_app_packet);

    ctx->set_phase (SEND_ENC);

}