#include <packet.h>
#include <ctx.h>
#define DEBUG
#ifdef DEBUG
#include <stdio.h>
#include <unistd.h>
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
    // 1. send the head 
	SecPacket *sec_packet = ctx->payload.secPacket;

    fprintf(stderr,"%x\n", sec_packet->head);

    fprintf(stderr,"%d\n", ctx->write_file);

	if(Write(fileno(ctx->write_file), sec_packet->head, SEC_HEAD_LEN) != SEC_HEAD_LEN)
    {
        fprintf(stderr,"error in write file");
    }
	// 2. send the payload
    fprintf(stderr,"here");
	int len = *(int *)(sec_packet->head+4);
	#ifdef DEBUG 
	fprintf(stderr, "[%s:%d] length : %d\n", __FILE__, __LINE__, len);
	fprintf(stderr, "send to : %lx\n", ctx->write_file);
	#endif
	Write(fileno(ctx->write_file), sec_packet->payload.data, len);
end :
    return flag;

}