#include <packet.hpp>

#ifdef DEBUG 
#include<iostream>
#endif


using namespace packet;

void Packet::handle_verify() {
    PacketCTX *ctx = get_ctx();
    ctx->set_phase(RECV_APP_PACKET);

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
        /* 获取顶级的sP */
        IBEPublicParameters mpk = NULL;

        // if(!ibe_verify(data2, data_len, sign_data, sign_len, &mpk, 239, SERVER_ID, SERVER_ID_LEN))
        // {
        //     fprintf(stderr, "verify error\n");
        //     goto end;
        // }

    }
    else
    {
        SignMesg *verify_sign;
        verify_sign = sign;
        while(verify_sign->front!=nullptr)
        {

        }
    }
    
    
}