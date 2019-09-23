#include <packet.h>
// #define DEBUG

int packet_handle(PacketCTX* ctx) {
    int flag = 1;
    while(ctx->phase != RECV_DONE && flag!=0) {
        #ifdef DEBUG 
        fprintf(stderr, "handle phase : %d\n", ctx->phase);
        #endif
        switch (ctx->phase)
        {
        case RECV_APP_PACKET:
            flag = handle_ap(ctx);
            break;
        case RECV_VERIFY:
            flag = handle_verify(ctx);
            break;
        case RECV_DEC:
            flag = handle_dec(ctx);
            break;
        case RECV_SEC_PACKET:
            flag = handle_sp(ctx);
            break;
        }
    }

    #ifdef DEBUG 
    fprintf(stderr, "flag : %d\n", flag);
    #endif 

    return flag;
}