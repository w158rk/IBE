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

#define DEBUG

using namespace user;


/* 
 * internal functions
 */ 

void Client::run_get_private_key(char *server_ip, 
								int server_port,
								ID *server_id)
{
	if(server_id == nullptr) {
		server_id = get_id()->father_node;
	}

	/* connect to the server first */
	interface::IComm *comm = get_comm_ptr();
	comm->connect_to_server(server_ip, server_port);

	// QUESTION : is it necessary to run a listening thread for the connection ?	
	// try
	// {
	// 	comm->file_main();
	// }
	// catch(const std::exception& e)
	// {
	// 	std::cerr << e.what() << '\n';
	// 	throw e;
	// }

	/**
	 * the format of the head is:
	 * --------------------------------------
	 * |	type	|	length of payload   |
	 * --------------------------------------
	 * the format of the payload is :
	 * 	--------------------------
	 * 	|	sm4_key 	|	ID   |
	 * 	-------------------------- 
	 */

	/* get the id */
	char *id = get_id()->id;
	size_t id_len = get_id()->length;		// the upper integer of (id_len+1)
	size_t m_len = (size_t)(id_len + SM4_KEY_LEN);
	char *payload = (char *)std::malloc(m_len);

	AppPacket *p_app_packet = new AppPacket; 
	
	/* set the head */
	*(int *)(p_app_packet->head) = PRIVATE_KEY_REQUEST_TYPE;		//AppPacket.head的第一位为1（标志位，标志为申请私钥）
	*(int *)(p_app_packet->head + 4) = m_len;		//从AppPacket.head的第4位开始存放payload的长度

	/* generate and copy the sm4 key */

	// GENERATE_SM4_FILENAME(id, id_len)
	// #ifdef DEBUG
	// fprintf(stderr, "filename is:%s\n", filename);
	// #endif
	// FILE *fp;
	// if((fp=fopen(filename,"wb+"))==NULL)
    // {
    //     printf("file cannot open \n");
    // }
	unsigned char key[SM4_KEY_LEN];
	set_sm4key(key);
	// set_key(key,fp);		//生成16位的key
	// fclose(fp);
	// FREE_SM4_FILENAME;
	memcpy(payload, key, SM4_KEY_LEN);		//把key复制到p中

#ifdef DEBUG 
	fprintf(stderr, "[%s : %d] payload1 : %s\n", __FILE__, __LINE__, payload);
#endif

	/* copy the id */
	memcpy(payload+SM4_KEY_LEN, id, (size_t)id_len);		
	p_app_packet->payload = payload;

#ifdef DEBUG 
	fprintf(stderr, "[%s : %d] payload2 : %s\n", __FILE__, __LINE__, payload);
#endif

	PacketCTX *ctx = new PacketCTX;
	// NOTE : It is the responsibility of packet class to 
	// free every packet-ctx generated by any module

	ctx->phase = SEND_APP_PACKET;
	ctx->payload.appPacket = p_app_packet;
	ctx->dest_id = server_id;

#ifdef DEBUG
	fprintf(stderr, "send sm4_key is:\n");
	for(int t=0;t<16;t++)
		printf("%02x ",ctx->payload.appPacket->payload[t]);
	printf("\n");
#endif

	// this code is a little weird, but it works 
	// to get the mpk into the ctx

	IBEPublicParameters mpk = NULL;
	get_mpk_fp(get_mpk_filename(), &mpk);		//从文件中读出sP的值
	
#ifdef DEBUG 
	fprintf(stderr, "[%s : %d] phase : %d\n", __FILE__, __LINE__, ctx->phase);
#endif

	ctx->mpk = mpk;		//将sP放入包中
#ifdef DEBUG 
	fprintf(stderr, "[%s : %d] phase : %d\n", __FILE__, __LINE__, ctx->phase);
#endif

	if(0 == get_packet_ptr()->packet_send(ctx)) {
		throw UserException("wrong when make the packet to send");
	}


}

void User::run_send_message(char *dest_ip, 
					int dest_port,
					ID *dest_id)
{

	interface::IComm *comm = get_comm_ptr();
	comm->connect_to_server(dest_ip, dest_port);
	
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

	#ifdef DEBUG
	fprintf(stderr, "%s\n", filename_message);
	#endif
	
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
	#ifdef DEBUG
	fprintf(stderr, "the message is:%s\n", message);
	fprintf(stderr, "the length of message is:%d\n", len);
	#endif

	/* 组织包 */

	AppPacket *p_app_packet = new AppPacket ; 
	
	/* set the head */
	/**
	 * the format is : 
	 * --------------------------------------
	 * |	type	|	length of payload	|
	 * --------------------------------------
	 */
	*(int *)(p_app_packet->head) = IBE_MES_TYPE;		//设置标志位
	*(int *)(p_app_packet->head + 4) = len;
	p_app_packet->payload = message;

	PacketCTX *ctx = new PacketCTX;

	ctx->phase = SEND_APP_PACKET;
	ctx->payload.appPacket = p_app_packet;
	ctx->dest_id = dest_id;

	IBEPublicParameters mpk = NULL;
	get_mpk_fp(get_mpk_filename(), &mpk);

	ctx->mpk = mpk;		//将sP放入包中
#ifdef DEBUG 
	fprintf(stderr, "[%s : %d] phase : %d\n", __FILE__, __LINE__, ctx->phase);
#endif

	if(0 == get_packet_ptr()->packet_send(ctx)) {
		throw UserException("wrong when make the packet to send");
	}


}