/**
 * @file send_s.c
 * @author Wang Ruikai 
 * @date August 9th, 2019 
 * @brief add signature to the sec packet
 */

#include<packet.h>
#include <string.h>

int send_sign(PacketCTX *ctx)
{
    int rtn = 0;

    ctx->phase = SEND_ENC;

    rtn = 1;
end:
    return rtn;
}