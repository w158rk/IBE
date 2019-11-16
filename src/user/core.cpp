/*****************************************************************************
Copyright: ...
File name: core.c
Description: 主要的应用函数，对外接口函数 	：		socket_main
Author: 王瑞凯
Version: ...
Date: 2019-06-16
History: ...
*****************************************************************************/

#include <user.hpp>
#include <iostream>
#include <config.h>

extern "C" {
	#include <crypto.h>
	#include <string.h>
	#include <sys.h>
	#include<utils.h>
}



using namespace user;


/* 
 * internal functions
 */ 



void User::run_send_message(char *dest_ip, 
					int dest_port,
					ID *dest_id)
{

	
	// try
	// {
	// 	comm->file_main();
	// }
	// catch(const std::exception& e)
	// {
	// 	std::cerr << e.what() << '\n';
	// 	throw e;
	// }

	/* 需要加密的文件放在id_message.txt中 */
	fprintf(stderr, "len is%d\n", dest_id->length);
	int filename_message_len = dest_id->length + 13;
	char *filename_message = (char *)malloc(filename_message_len);
	memcpy(filename_message, dest_id->id, dest_id->length);
	memcpy(filename_message+dest_id->length, "_message.txt", 14);

	/* 读取信息 */
	FILE *fp;
	if((fp=fopen(filename_message,"rb+"))==NULL)
    {
        printf("file_massge cannot open \n");
		throw std::exception();
    }
	char *message = (char *)malloc(MES_LEN);
	if(!fread(message, sizeof(char), MES_LEN, fp))
	{
		printf("error in read file \n");
		throw std::exception();
	}
	fclose(fp);
	int len = strlen(message);

	/* 组织包 */

	AppPacket *p_app_packet = new AppPacket ; 
	
	/* set the head */
	/**
	 * the format is : 
	 * --------------------------------------
	 * |	type	|	length of payload	|
	 * --------------------------------------
	 */
	p_app_packet->set_type(IBE_MES_TYPE);
	p_app_packet->set_length(len);
	p_app_packet->set_payload(message);

	PacketCTX *ctx = new PacketCTX;

	ctx->set_phase(SEND_APP_PACKET);
	ctx->set_payload_app (p_app_packet);
	ctx->set_dest_id(dest_id);

	IBEPublicParameters mpk = NULL;
	get_mpk_fp(get_mpk_filename(), &mpk);

	ctx->set_mpk(&mpk);		//将sP放入包中

	interface::IComm *comm = get_comm_ptr();
	comm->connect_to_server(dest_ip, dest_port);

	// must connect to the server before this point
	if(0 == get_packet_ptr()->packet_send(ctx)) {
		throw UserException("wrong when make the packet to send");
	}

}



# define MAKE_APP_PACKET(type) \
	AppPacket *p_app_packet = new AppPacket ; \
	int id_length = get_id()->length;	\
	int payload_len = length +  id_length + 5; \
	/* for convenience, we add a '\0' at the end */\
	char *buffer = (char *)std::malloc(payload_len);	\
	buffer[payload_len-1] = '\0';				\
	set_int(buffer, get_id()->length);	\
	std::memcpy(buffer+4, get_id()->id, id_length);	\
	std::memcpy(buffer+4+id_length, buff, length);	\
	p_app_packet->set_type(type);	\
	p_app_packet->set_length(payload_len);			\
	p_app_packet->set_payload(buffer);		

# define MAKE_CTX \
	PacketCTX *ctx = new PacketCTX;	\
	ctx->set_phase(SEND_APP_PACKET);	\
	ctx->set_payload_app (p_app_packet);	\
	ctx->set_dest_id(dest_id);		

# define CONNECT_AND_SEND(dest_ip, dest_port)	\
	interface::IComm *comm = get_comm_ptr();	\
	comm->connect_to_server(dest_ip, dest_port);	\
	if(0 == get_packet_ptr()->packet_send(ctx)) {	\
		throw UserException("send the packet error");	\
	}


void User::send_init_message_1(char *buff, int length, ID *dest_id)
{
	MAKE_APP_PACKET(INIT_MESSAGE_1)
	MAKE_CTX
	CONNECT_AND_SEND(dest_id->ip, dest_id->port)
}

void User::send_init_message_2(char *buff, int length, ID *dest_id)
{
	MAKE_APP_PACKET(INIT_MESSAGE_2)
	MAKE_CTX
	CONNECT_AND_SEND(dest_id->ip, dest_id->port)	
}

void User::send_init_message_3(char *buff, int length, ID *dest_id)
{
	MAKE_APP_PACKET(INIT_MESSAGE_3)
	MAKE_CTX
	CONNECT_AND_SEND(dest_id->ip, dest_id->port)	
}

