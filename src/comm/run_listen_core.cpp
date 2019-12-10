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
	#include <string.h>
}
#include "comm_lcl.hpp"

#include <sstream>
#include <iostream>

using namespace comm;

#define Error(err) throw CommException(err)

/*读取包的内容和处理包的过程*/
int Comm::run_listen_core()
{
	// init the static variable
	ID *entity_id = user_get_id(get_user_ptr()); 
	char *entity_id_cstr = entity_id->id;
	int entity_id_len = entity_id->length; 

	/* now I have got the crypto type, so what I should do is to get the plain text
		* from the packet 
		* */
	char buffer[BUFFER_SIZE];

	// read the data stream and reorganize it as a security packet
	// SecPacket *p_packet = (SecPacket *)malloc(sizeof(SecPacket));

	// read the head
	FILE *read_file = get_read_file();
	if(!fread(buffer, sizeof(char), SEC_HEAD_LEN, read_file))
	{
		if(feof(read_file))
		{
			get_ui_ptr()->error("client close its connection abruptly");
			return -1;
		}
		else
		{
			std::ostringstream buffer; 
			buffer << "can't get user request: " << strerror(errno);
			Error(buffer.str());
		}
	}

	#ifdef DEBUG 
	get_ui_ptr()->debug("finish reading the head");
	#endif

	// read sign
	if(!fread(buffer+SEC_HEAD_LEN, sizeof(char), IBE_SIGN_LEN, read_file))
	{
		if(feof(read_file))
		{
			get_ui_ptr()->error("client close its connection abruptly");
			return -1;
		}
		else
		{
			std::ostringstream buffer; 
			buffer << "can't get user request: " << strerror(errno);
			Error(buffer.str());
		}
	}

	#ifdef DEBUG 
	get_ui_ptr()->debug("finish reading the sign");
	#endif

	// length of the packet without the head
	int length = *(int *) (buffer+TYPE_LEN+ID_LEN_MAX);

	if(!fread(buffer+SEC_HEAD_LEN+IBE_SIGN_LEN, sizeof(char), length, m_read_file))
	{
		if(feof(m_read_file))
		{
			get_ui_ptr()->error("client close its connection abruptly");
			return -1;
		}
		else
		{
			std::ostringstream buffer; 
			buffer << "can't get user request: " << strerror(errno) << std::endl;
			buffer << "the length of reading: " << length << std::endl;
			Error(buffer.str());
		}
	}
	#ifdef DEBUG 
	get_ui_ptr()->debug("finish reading the payload");
	#endif
	SecPacket *p_sec_packet = SecPacket::from_bytes(buffer);

	// handle the packet
	PacketCTX *p_ctx = new PacketCTX;

	p_ctx->set_phase(RECV_SEC_PACKET);
	p_ctx->set_payload_sec(p_sec_packet);
	p_ctx->set_dest_id(entity_id);

	if(get_packet_ptr()->packet_handle(p_ctx) == -1)
	{
		get_ui_ptr()->error("handle packet received error");
		return -1;
	}

	delete p_ctx;
	p_ctx = nullptr;

#ifdef DEBUG 
	get_ui_ptr()->debug("handle received packet finished ");
#endif

	return 0;
}


