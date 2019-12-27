/**
 * @file send_s.c
 * @author Wang Ruikai 
 * @date August 9th, 2019 
 * @brief add signature to the sec packet
 */

extern "C" {
#include <sys.h>
#include<config.h>
#include <string.h>
}

#include<packet.hpp>

#include "packet_lcl.hpp"

using namespace packet;

void Packet::send_sign()
{
    PacketCTX *ctx = get_ctx();

    if(ctx->get_phase() != SEND_SIGN) {
        interface::IUI::error("call wrong function");
        throw PacketException("call wrong function");
    }

    SecPacket *p_sec_packet = ctx->get_payload_sec();
    AppPacket *p_packet = p_sec_packet->get_payload_app();
    int type = p_packet->get_type();

    if(type==IBE_MES_TYPE)
    {
        char data[BUFFER_SIZE];
        int app_length = p_packet->get_length();
        int len = (size_t)app_length+APP_HEAD_LEN;
        memcpy(data, p_packet->to_bytes(), len);

        char sign_data[BUFFER_SIZE] = {'\0'};
        size_t sign_len;

        IBEPrivateKey sk = NULL;

        char *filename = NULL;
        user::User *user_ptr = get_user_ptr();
        ID *user_id = user_get_id(user_ptr);

        filename = user_get_sk_filename(user_ptr);
        get_sk_fp(filename, &sk);
        free(filename);
        
        if(!(ibe_sign(data, len, sign_data, &sign_len, &sk, 380)))
        {
            fprintf(stderr, "sign error\n");
        }

        p_sec_packet->set_signature(sign_data);

    }
    else
    {
        char sign_data[IBE_SIGN_LEN] = {'\0'};
        p_sec_packet->set_signature(sign_data);
    }
    

    ctx->set_phase (SEND_ENC);

}