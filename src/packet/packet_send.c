#include <packet.h>
// # define DEBUG
#ifdef DEBUG
#include <stdio.h>
#endif

int packet_send(PacketCTX* ctx) {
    int flag = 1;
    while(ctx->phase != SEND_DONE && flag!=0) {
        #ifdef DEBUG 
        fprintf(stderr, "phase : %d\n", ctx->phase);
        #endif
        switch (ctx->phase)
        {
        case SEND_APP_PACKET:
            flag = send_ap(ctx);
            break;
        case SEND_SIGN:
            flag = send_sign(ctx);
            break;
        case SEND_ENC:
            flag = send_enc(ctx);
            break;
        case SEND_SEC_PACKET:
            flag = send_sp(ctx);
            break;
        }
    }

end :
    return flag;

}