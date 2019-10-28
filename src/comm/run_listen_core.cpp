/*****************************************************************************
Copyright: ...
File name: conenction.c
Description: 关于监听socket的建立和与服务器的连接的函数
Author: 王瑞凯
Version: ...
Date: 2019-06-16
History: ...
*****************************************************************************/

extern "C" {
	#include <errno.h>
	#include <config.h>
	#include <stdio.h>
	#include <string.h>
}
#include <comm.hpp>
// static long int current_client_id;

#ifdef DEBUG 
	#include <iostream>
#endif

using namespace comm;

/*读取包的内容和处理包的过程*/
int Comm::run_listen_core()
{
	// init the static variable
	int current_client_id = -1;
	ID *entity_id = m_user_ptr->get_id(); 
	char *entity_id_cstr = entity_id->id;
	int entity_id_len = entity_id->length; 

#ifdef DEBUG 
	std::cerr << "listen comm: " << (unsigned long)this << std::endl;
#endif

	do
	{
		/* now I have got the crypto type, so what I should do is to get the plain text
		 * from the packet 
		 * */
		#ifdef DEBUG 
		fprintf(stderr, "listening...\n");
		#endif
		char buffer[BUFFER_SIZE];

		// read the data stream and reorganize it as a security packet
		SecPacket *p_packet = (SecPacket *)malloc(sizeof(SecPacket));

		// read the head
		FILE *read_file = get_read_file();
		if(!fread(p_packet->head, sizeof(char), SEC_HEAD_LEN, read_file))
		{
			if(feof(read_file))
			{
				fprintf(stdout, "client close its connection abruptly\n");
				return 0;
			}
			else
			{
				fprintf(stderr, "can't get user request: %s\n", strerror(errno));
				return -1;
			}
		}

		#ifdef DEBUG 
		fprintf(stderr, "finish reading the head\n");
		fprintf(stderr, "type : %d\n", *(int *)(p_packet->head));
		fprintf(stderr, "length : %d\n", *(int *)(p_packet->head+4));
		#endif
		// length of the packet without the head
		int length = *(int *) (p_packet->head+4);

		// read the payload 
		char *payload = (char *) malloc(length);
		if(!fread(payload, sizeof(char), length, m_read_file))
		{
			if(feof(m_read_file))
			{
				fprintf(stdout, "client close its connection abruptly\n");
				return 0;
			}
			else
			{
				fprintf(stderr, "can't get user request: %s\n", strerror(errno));
				return -1;
			}
		}
		#ifdef DEBUG 
		fprintf(stderr, "finish reading the payload\n");
		#endif
		p_packet->payload.data = payload;

		// handle the packet
		PacketCTX *ctx = new PacketCTX;

		ctx->phase = RECV_SEC_PACKET;
		ctx->payload.secPacket = p_packet;
		ctx->dest_id = entity_id;				// the id of the runner itself 

		if(m_packet_ptr->packet_handle(ctx) == -1)
		{
			fprintf(stderr, "handle IBE packet error\n");
			return -1;
		}
		break;

	} while(1);				// 客户端关闭之前一直执行

	return 0;
}


