#include <packet.hpp>

void packet::free_sec_packet(SecPacket *packet)
{
    /* free the payload */
    if(packet->payload.data != nullptr)
    {
        std::free(packet->payload.data);
    }

    delete packet;
}

void packet::free_app_packet(AppPacket *packet)
{
    /* free the packet */ 
    if(packet->payload != nullptr)
    {
        std::free(packet->payload);
    }
    delete packet;
}

void packet::free_ctx(PacketCTX *ctx)
{
    AppPacket *packet = ctx->payload.appPacket;
    if(packet != nullptr)
    {
        free_app_packet(packet);
    }
    ctx->payload.appPacket = nullptr;

    
    /* free the IDs */ 
    if(ctx->src_id != nullptr) delete ctx->src_id;
    if(ctx->dest_id != nullptr) delete ctx->dest_id;

    /* free the mpk and sk */
    
    // I don't know where they are assigned
    
    // if(ctx->mpk != nullptr) std::free(ctx->mpk);
    // if(ctx->sk != nullptr) std::free(ctx->sk);

    /* free the key */
    if(ctx->key != nullptr) std::free(ctx->key);
    delete ctx;
}