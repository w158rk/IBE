/*****************************************************************************
Copyright: ...
File name: core.c
Description: 主要的应用函数，对外接口函数 	：		socket_main
Author: 王瑞凯
Version: ...
Date: 2019-06-16
History: ...
*****************************************************************************/



#include "base.h"
#include <ctx.h>
#include <crypto.h>
#include <packet.h>
#include <sys.h>
// #define __DEBUG__


/* 
 * internal functions
 */ 

int run_get_private_key(const char* id, int id_len) {

	int ret = 0;
	/* connect to the server first */
	connect_socket_server(SERVER_IP_ADDRESS, SERVER_LISTEN_PORT, &read_file, &write_file);

	/* arrange the private key request message */
	size_t actual_id_len = ((id_len+4)/4) * 4;		// the upper integer of (id_len+1)
	size_t m_len = (size_t)(actual_id_len + AES_KEY_LEN);
	char *payload = (char *)malloc(m_len);
	memset(payload, 0, m_len);

	AppPacket packet; 
	/* set the head */
	*(int *)(packet.head) = PRIVATE_KEY_REQUEST_TYPE;
	*(int *)(packet.head + 4) = m_len;

	
	/* generate and copy the aes key */
	char *p = payload;
	char key[AES_KEY_LEN];
	gen_random_key(key);
	memcpy(p, key, AES_KEY_LEN);
	packet.payload = payload;

	/* copy the id */
	p += AES_KEY_LEN;
	memcpy(p, id, (size_t)id_len);

	#ifdef DEBUG 
	fprintf(stderr, payload);
	#endif
	/* set the context */
	memcpy(aes_key, key, AES_KEY_LEN);

	PacketCTX ctx;

	ctx.phase = SEND_APP_PACKET;
	ctx.payload.appPacket = &packet;
	ctx.read_file = read_file;
	ctx.write_file = write_file;
	ctx.dest_id = SERVER_ID;
	ctx.dest_id_len = SERVER_ID_LEN;

	// this code is a little wierd, but it works 
	// to get the mpk into the ctx

	IBEPublicParameters mpk = NULL;
	get_mpk_fp(MPK_FILENAME, &mpk);
	
	#ifdef DEBUG 
	fprintf(stderr, "[%s : %d] phase : %d\n", __FILE__, __LINE__, ctx.phase);
	#endif
	ctx.mpk = &mpk;
	#ifdef DEBUG 
	fprintf(stderr, "[%s : %d] phase : %d\n", __FILE__, __LINE__, ctx.phase);
	#endif

	if(0 == packet_send(&ctx)) {
		ERROR("wrong when make the packet to send");
		goto end;
	}

	// send the packet through the socket 
	// 1. send the head 
	SecPacket *sec_packet = ctx.payload.secPacket;
	Write(fileno(write_file), sec_packet->head, SEC_HEAD_LEN);
	// 2. send the payload
	int len = *(int *)(sec_packet->head+4);
	#ifdef DEBUG 
	fprintf(stderr, "[%s:%d] length : %d\n", __FILE__, __LINE__, len);
	#endif
	Write(fileno(write_file), sec_packet->payload.data, len);

	ret = 1;

end:
	free(payload);
	return ret;

}
