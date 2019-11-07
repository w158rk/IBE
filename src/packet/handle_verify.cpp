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

}