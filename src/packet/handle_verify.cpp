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
#ifdef DEBUG       
    std::cerr << " type: " << ctx->get_payload_app()->get_type() << std::endl;
#endif

    AppPacket *p = ctx->get_payload_app();
    int type = p->get_type();
    char *id = packet->get_id();
    p->set_id(id);
    if(type==IBE_MES_TYPE)
    {
        char *sign = packet->get_signature();
#ifdef DEBUG
        fprintf(stderr, "id is %s\n", id);
#endif
        IBEPublicParameters mpk = NULL;
        GENERATE_MPK_FILENAME(id,strlen(id))
        get_mpk_fp(mpk_filename, &mpk);
        FREE_MPK_FILENAME;

        int length = p->get_length();

        char *message = p->get_payload();

        if(!ibe_verify(message, length, sign, IBE_SIGN_LEN, &mpk, 239, id, strlen(id)))
        {
            fprintf(stderr, "verify error\n");
        }
        else
        {
            fprintf(stderr, "verify done\n");
        }

    }
    ctx->set_phase(RECV_APP_PACKET);

    
    
}