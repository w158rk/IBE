/**
 * @file send_sp.c
 * @author Wang Ruikai 
 * @date August 9th, 2019 
 * @brief convert the sec packet into char array
 */

#include<packet.h>
#include <crypto.h>
#include <string.h>

int send_sp(PacketCTX *ctx)
{
    int rtn = 0;

    if(ctx->phase != SEND_SEC_PACKET) {

        ERROR("call wrong function");
        goto end;
    }
    #ifdef DEBUG
    fprintf(stderr,"enc_sk is :%s\n",ctx->payload.secPacket->payload.data);
    #endif
    ctx->phase = SEND_DONE;
    rtn = 1;
end:
    return rtn;
}