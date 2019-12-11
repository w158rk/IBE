/**
 * @file send_ap.c
 * @author Wang Ruikai 
 * @date August 9th, 2019 
 * @brief send the packet in the App Packet level
 */


extern "C" {
#include <string.h>
}

#include<config.h>
#include"packet_lcl.hpp"
#include<crypto.h>
using namespace packet;

void Packet::send_ap()
{   
    user::User *user_ptr = get_user_ptr();
    PacketCTX *ctx = get_ctx();

    if(ctx->get_phase() != SEND_APP_PACKET) {
        ERROR("call wrong function");
        throw std::exception();
    }

    AppPacket *p_packet = ctx->get_payload_app();
    char *p_head = p_packet->get_head();
    int send_type;
    int type = p_packet->get_type();

    switch (type)
    {
        case PLAIN_MESSAGE_TYPE:
        case PRIVATE_KEY_RESPONSE_TYPE:
        case SESSION_KEY_FINAL_TYPE:
            send_type = SM4_TYPE;
            break;
        
        case PRIVATE_KEY_REQUEST_TYPE:
        {
            char *p_sm4key = (char *)std::malloc(SM4_KEY_LEN);
            memcpy(p_sm4key, p_packet->get_payload(), SM4_KEY_LEN);
            user_set_sm4_key(user_ptr, p_sm4key);
            send_type = IBE_TYPE;
            break;
        }

        case SESSION_KEY_ACK_TYPE:
        case IBE_MES_TYPE:
            send_type = IBE_DOMAIN_TYPE;
            break;

        default:
            send_type = NO_ENC_TYPE;
    }

    // make a sec packet, 
    // the payload is an app packet and no length infomation set 
    // length infomatino is set in end phase
    SecPacket *p_send_packet = new SecPacket;  

    p_send_packet->set_type(send_type);
    ID *user_id = user_get_id(user_ptr);
    p_send_packet->set_id(user_id->id);
    p_send_packet->set_payload_app(p_packet);
    ctx->set_payload_sec(p_send_packet);
    ctx->set_phase(SEND_SIGN);
}