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
#include <openssl/sm4.h>
#include <sys.h>
#define DEBUG


/* 
 * internal functions
 */ 

int run_get_private_key(const char* id, int id_len) {

	int ret = 0;
	/* connect to the server first */
	connect_socket_server(SERVER_IP_ADDRESS, SERVER_LISTEN_PORT, &read_file, &write_file);
	
	#ifdef DEBUG
	fprintf(stderr, "[%s:%d] mark\n", __FILE__, __LINE__);
	fprintf(stderr, "[%s:%d] read from %lx\n", __FILE__, __LINE__, read_file);
	fprintf(stderr, "[%s:%d] write to %lx\n", __FILE__, __LINE__, write_file);	
	fprintf(stderr, "[%s:%d] %ld\n", __FILE__, __LINE__, sizeof(write_file));	
	#endif
	
	if(file_main(id, id_len, read_file, write_file) == -1) {
		fprintf(stderr, "[%s:%d] something went wrong\n", __FILE__, __LINE__);
		return -1;
	}

	#ifdef DEBUG 
	fprintf(stderr, "[%s:%d] mark\n", __FILE__, __LINE__);
	#endif
	/* arrange the private key request message */
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
	int filename_len = id_len + 10;
    char *filename = (char *)malloc(filename_len);
    filename[0] = 's';
    filename[1] = 'm';
    filename[2] = '4';
	filename[3] = '_';
    memcpy(filename+4, id, id_len);
    filename[filename_len-6] = '.'; 
    filename[filename_len-5] = 'c'; 
    filename[filename_len-4] = 'o'; 
    filename[filename_len-3] = 'n'; 
    filename[filename_len-2] = 'f';
    filename[filename_len-1] = '\0';
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
	#ifdef DEBUG
	FILE *fp2;
    if((fp2=fopen(filename,"rb+"))==NULL)
    {
        printf("file cannot open \n");  
    }
	get_key(key, fp2);
	printf("从文件中读出key:");
	for(int t=0;t<16;t++)
		printf("%02x ",key[t]);
	printf("\n");
    fclose(fp2);
	#endif
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
	/* set the context */
	memcpy(sm4_key, key, SM4_KEY_LEN);		//改变sm4_key中的内容为新生成的key

	/*组织包*/
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
	get_mpk_fp(MPK_FILENAME, &mpk);		//从文件中读出sP的值
	
	#ifdef DEBUG 
	fprintf(stderr, "[%s : %d] phase : %d\n", __FILE__, __LINE__, ctx.phase);
	#endif
	ctx.mpk = &mpk;		//将sP放入包中
	#ifdef DEBUG 
	fprintf(stderr, "[%s : %d] phase : %d\n", __FILE__, __LINE__, ctx.phase);
	#endif

	if(0 == packet_send(&ctx)) {
		ERROR("wrong when make the packet to send");
		goto end;
	}
	// send the packet through the socket 
	// 1. send the head 

	/*SecPacket *sec_packet = ctx.payload.secPacket;
	Write(fileno(write_file), sec_packet->head, SEC_HEAD_LEN);
	// 2. send the payload
	int len = *(int *)(sec_packet->head+4);
	#ifdef DEBUG 
	fprintf(stderr, "[%s:%d] length : %d\n", __FILE__, __LINE__, len);
	#endif
	Write(fileno(write_file), sec_packet->payload.data, len);*/

	ret = 1;

end:
	free(payload);
	return ret;

}
