#include <packet.hpp>
#include <string.h>
#include <sys.h>

#ifdef DEBUG 
#include<iostream>
#endif


using namespace packet;

void Packet::handle_verify() {
    PacketCTX *ctx = get_ctx();
    ctx->set_phase(RECV_APP_PACKET);

    /* 从ctx包中获取发送方的ID及sP */
    IBEPublicParameters *mes_mpk = NULL;
    mes_mpk = ctx->get_mpk();
    char *mes_id;
    mes_id = ctx->get_src_id()->id;
    size_t id_len = strlen(mes_id);
    char *data = (char *)malloc(id_len + IBE_MPK_LEN);
    memcpy(data, mes_mpk, IBE_MPK_LEN);
    memcpy(data + IBE_MPK_LEN, mes_id, id_len);

#ifdef DEBUG       
    std::cerr << " type: " << ctx->get_payload_sec()->get_payload_app()->get_type() << std::endl;
#endif

    SecPacket *packet = ctx->get_payload_sec();
    ctx->set_payload_app(packet->get_payload_app());
    delete packet;
#ifdef DEBUG       
    std::cerr << " type: " << ctx->get_payload_app()->get_type() << std::endl;
#endif

    AppPacket *p = packet->get_payload_app();
    SignMesg *sign;
    sign = p->get_sign();
    if(sign->front==nullptr)
    {
        if(!strcmp(mes_id, sign->ID)||!strcmp((char *)mes_mpk, (char *)sign->PP))
        {
            fprintf(stderr, "verify error\n");
        }

        /* 获取顶级的sP */
        IBEPublicParameters mpk = NULL;

        if(!ibe_verify(data, id_len + IBE_MPK_LEN, sign->sign_data, strlen(sign->sign_data), &mpk, 239, ctx->get_src_id()->father_node->id, strlen(ctx->get_src_id()->father_node->id)))
        {
            fprintf(stderr, "verify error\n");
        }  

    }
    else
    {
        SignMesg *verify_sign;
        verify_sign = sign;
        while(verify_sign->front!=nullptr)
        {
            verify_sign = sign->front;

        }
    }
    
    
}