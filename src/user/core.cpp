/*****************************************************************************
Copyright: ...
File name: core.c
Description: 主要的应用函数，对外接口函数 	：		socket_main
Author: 王瑞凯
Version: ...
Date: 2019-06-16
History: ...
*****************************************************************************/
#include "user_lcl.hpp"
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

#define Debug(info) get_ui_ptr()->debug(info)

/* 
 * internal functions
 */ 

void User::try_send_message(char *dest_ip, 
					int dest_port,
					ID *dest_id)
{

	interface::IComm *comm = get_comm_ptr();
	comm->connect_to_server(dest_ip, dest_port);

	// QUESTION : is it necessary to run a listening thread for the connection ?	
	 try
	 {
		// get the files from the comm object
		comm_file_main(this, comm->get_read_file(), 
									comm->get_write_file());
	 }
	 catch(const std::exception& e)
	 {
	 	std::cerr << e.what() << '\n';
	 	throw e;
	 }

	GENERATE_SIGN_LEN_FILENAME(User::get_id()->id, strlen(User::get_id()->id)) 

	FILE *fp1; 
	if((fp1=fopen(filename_len_sign,"rb"))==NULL)
	{
		interface::IUI::error("file cannot open \n");  
	}
	int sign_len;
	std::fread(&sign_len, sizeof(sign_len), 1, fp1);
	fclose(fp1);

	FREE_SIGN_LEN_FILENAME;

	GENERATE_SIGN_FILENAME(User::get_id()->id, strlen(User::get_id()->id)) 

	FILE *fp;
	if((fp=fopen(filename_sign,"rb+"))==NULL)
	{
		interface::IUI::error("file cannot open \n");  
	}
	char *sign = (char*)malloc(sign_len);
	if(!fread(sign, 1, sign_len, fp))
	{
		printf("error in read file \n");
		throw std::exception();
	}
	fclose(fp);

	FREE_SIGN_FILENAME;

	IBEPublicParameters mpk = NULL;

	if(User::get_id()->father_node!=nullptr)
	{
		GENERATE_MPK_FILENAME(User::get_id()->father_node->id,strlen(User::get_id()->father_node->id))
		get_mpk_fp(mpk_filename, &mpk);
		FREE_MPK_FILENAME;
	}
	else
	{
		get_mpk_fp(GLOBAL_MPK_FILENAME, &mpk);
	}

	char *payload = (char *)malloc(sign_len+IBE_MPK_LEN);
	memcpy(payload, mpk, IBE_MPK_LEN);
	memcpy(payload+IBE_MPK_LEN, sign, sign_len);

	/* 组织包 */

	AppPacket *p_app_packet = new AppPacket ; 
	
	/* set the head */
	/**
	 * the format is : 
	 * --------------------------------------
	 * |	type	|	length of payload	|
	 * --------------------------------------
	 */
	p_app_packet->set_type(TRY_MES_TYPE);
	p_app_packet->set_length(sign_len + IBE_MPK_LEN);
	p_app_packet->set_payload(payload);

	PacketCTX *ctx = new PacketCTX;

	ctx->set_phase(SEND_APP_PACKET);
	ctx->set_payload_app (p_app_packet);
	ctx->set_dest_id(dest_id);

	// must connect to the server before this point
	if(0 == get_packet_ptr()->packet_send(ctx)) {
		throw UserException("wrong when make the packet to send");
	}
	

}



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

	/* 需要加密的文件放在dest_id_message.txt中 */
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

void User::send_init_message_2(char *buff, int len1, int len2, ID *dest_id)
{
	AppPacket *p_app_packet = new AppPacket ; 
	int id_length = get_id()->length;	
	int payload_len = len1 + len2 +  id_length + 1 + 12; 
	/* for convenience, we add a '\0' at the end */
	char *buffer = (char *)std::malloc(payload_len);	
	buffer[payload_len-1] = '\0';				

	set_int(buffer, get_id()->length);	
	set_int(buffer+4, len1);	
	set_int(buffer+8, len2);	
	std::memcpy(buffer+12, get_id()->id, id_length);	
	std::memcpy(buffer+12+id_length, buff, len1+len2);	

#ifdef DEBUG 
{
	point_t *point = nullptr;
	if(!(ibe_point_from_octets(&point, buff+len1)))
	{
		Debug("ibe point from octets");
	}
	else {
		Debug("ibe point from octets success");
	}
}
#endif

	p_app_packet->set_type(INIT_MESSAGE_2);	
	p_app_packet->set_length(payload_len);			
	p_app_packet->set_payload(buffer);		

	MAKE_CTX
	CONNECT_AND_SEND(dest_id->ip, dest_id->port)	
}

void User::send_init_message_3(char *buff, int length, ID *dest_id)
{
	MAKE_APP_PACKET(INIT_MESSAGE_3)
	MAKE_CTX
	CONNECT_AND_SEND(dest_id->ip, dest_id->port)	
}

