#include <packet.hpp>
#include <string.h>
#include <sys.h>
#include <config.h>

#ifdef DEBUG 
#include<iostream>
#endif


using namespace packet;

void Packet::handle_verify() {
    PacketCTX *ctx = get_ctx();   
 
#ifdef DEBUG       
    std::cerr << " type: " << ctx->get_payload_sec()->get_payload_app()->get_type() << std::endl;
#endif

    SecPacket *packet = ctx->get_payload_sec();
    ctx->set_payload_app(packet->get_payload_app());
    delete packet;
#ifdef DEBUG       
    std::cerr << " type: " << ctx->get_payload_app()->get_type() << std::endl;
#endif

    AppPacket *p = ctx->get_payload_app();
    int type = p->get_type();
    if(type==IBE_MES_TYPE)
    {
        char *sign = packet->get_signature();

        IBEPublicParameters mpk = NULL;
        get_mpk_fp("mpk-Client.conf", &mpk);

        int length = p->get_length();

        char *message = p->get_payload();

        if(!ibe_verify(message, length, sign, IBE_SIGN_LEN, &mpk, 239, "Client", 6))
        {
            fprintf(stderr, "verify error\n");
        }

    }

    ctx->set_phase(RECV_APP_PACKET);

    
    
}