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

//#define DEBUG

using namespace user;


/* 
 * internal functions
 */ 

int Client::run_get_private_key(char *server_ip, 
								int server_port,
								ID *server_id)
{
	if(server_id == nullptr) {
		server_id = get_id()->father_node;
	}

	int ret = -1;
	
	/* connect to the server first */
	interface::IComm *comm = get_comm_ptr();
	comm->connect_to_server(server_ip, server_port);
	
	#ifdef DEBUG
	fprintf(stderr, "[%s:%d] mark\n", __FILE__, __LINE__);
	// fprintf(stderr, "[%s:%d] read from %lx\n", __FILE__, __LINE__, m_read_file);
	// fprintf(stderr, "[%s:%d] write to %lx\n", __FILE__, __LINE__, m_write_file);	
	#endif
	
	try
	{
		comm->file_main();
	}
	catch(const std::exception& e)
	{
		std::cerr << e.what() << '\n';
		throw e;
	}
	

	#ifdef DEBUG 
	fprintf(stderr, "[%s:%d] mark\n", __FILE__, __LINE__);
	#endif
	/* arrange the private key request message */
	char *id = get_id()->id;
	size_t id_len = get_id()->length;		// the upper integer of (id_len+1)
	size_t actual_id_len = ((id_len+4)/4) * 4;		// the upper integer of (id_len+1)
	size_t m_len = (size_t)(actual_id_len + SM4_KEY_LEN);
	char *payload = (char *)malloc(m_len);
	memset(payload, 0, m_len);		//初始化payload长度为id的长度加上SM4密钥的长度

	AppPacket packet; 
	/* set the head */
	*(int *)(packet.head) = PRIVATE_KEY_REQUEST_TYPE;		//AppPacket.head的第一位为1（标志位，标志为申请私钥）
	*(int *)(packet.head + 4) = m_len;		//从AppPacket.head的第4位开始存放payload的长度

	/* generate and copy the sm4 key */
	char *p = payload;
	GENERATE_SM4_FILENAME(id, id_len)
	#ifdef DEBUG
	fprintf(stderr, "filename is:%s\n", filename);
	#endif
	FILE *fp;
	if((fp=fopen(filename,"wb+"))==NULL)
    {
        printf("file cannot open \n");
    }
	unsigned char key[SM4_KEY_LEN];
	set_key(key,fp);		//生成16位的key
	fclose(fp);
	FREE_SM4_FILENAME;
	memcpy(p, key, SM4_KEY_LEN);		//把key复制到p中
	packet.payload = payload;		//AppPacket.payload存放sm4 key

	#ifdef DEBUG 
	fprintf(stderr, "[%s : %d] payload : %s\n", __FILE__, __LINE__, payload);
	#endif

	/* copy the id */
	p += SM4_KEY_LEN;		
	memcpy(p, id, (size_t)id_len);		//将id放在payload中

	#ifdef DEBUG 
	fprintf(stderr, "[%s : %d] payload : %s\n", __FILE__, __LINE__, payload);
	#endif

	/*组织包*/
	PacketCTX ctx;

	ctx.phase = SEND_APP_PACKET;
	ctx.payload.appPacket = &packet;
	ctx.dest_id = server_id;

	#ifdef DEBUG
	fprintf(stderr, "send sm4_key is:\n");
	fprintf(stderr, "payload is %s\n", ctx.payload.appPacket->payload);
	for(int t=0;t<16;t++)
		printf("%02x ",ctx.payload.appPacket->payload[t]);
	printf("\n");
	#endif

	// this code is a little wierd, but it works 
	// to get the mpk into the ctx

	IBEPublicParameters mpk = NULL;
	get_mpk_fp(MPK_FILENAME, &mpk);		//从文件中读出sP的值
	
	#ifdef DEBUG 
	fprintf(stderr, "[%s : %d] phase : %d\n", __FILE__, __LINE__, ctx.phase);
	#endif
	ctx.mpk = &mpk;		//将sP放入包中
	#ifdef DEBUG 
	fprintf(stderr, "[%s : %d] phase : %d\n", __FILE__, __LINE__, ctx.phase);
	#endif

	if(0 == get_packet_ptr()->packet_send(&ctx)) {
		ERROR("wrong when make the packet to send");
		goto end;
	}

	ret = 1;

end:
	free(payload);
	return ret;

}

int User::run_send_message(char *dest_ip, 
					int dest_port,
					ID *dest_id)
{
	int ret =-1;

	interface::IComm *comm = get_comm_ptr();
	comm->connect_to_server(dest_ip, dest_port);
	try
	{
		comm->file_main();
	}
	catch(const std::exception& e)
	{
		std::cerr << e.what() << '\n';
		throw e;
	}

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

	AppPacket packet; 
	/* set the head */
	*(int *)(packet.head) = IBE_MES_TYPE;		//设置标志位
	*(int *)(packet.head + 4) = len;
	packet.payload = message;

	PacketCTX ctx;

	ctx.phase = SEND_APP_PACKET;
	ctx.payload.appPacket = &packet;
	/*ctx.dest_id = SERVER_ID;
	ctx.dest_id_len = SERVER_ID_LEN;*/
	ctx.dest_id = dest_id;

	IBEPublicParameters mpk = NULL;
	get_mpk_fp(MPK_FILENAME, &mpk);

	ctx.mpk = &mpk;		//将sP放入包中
	#ifdef DEBUG 
	fprintf(stderr, "[%s : %d] phase : %d\n", __FILE__, __LINE__, ctx.phase);
	#endif

	if(0 == get_packet_ptr()->packet_send(&ctx)) {
		ERROR("wrong when make the packet to send");
		goto end;
	}

	ret = 1;

end:
	return ret;

}