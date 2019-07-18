/*****************************************************************************
Copyright: ...
File name: core.c
Description: 主要的应用函数，对外接口函数 	：		socket_main
Author: 王瑞凯
Version: ...
Date: 2019-06-16
History: ...
*****************************************************************************/



#include "../crypto/crypto.h"
#include "base.h"
#include <ctx.h>
// #define __DEBUG__


/* 
 * internal functions
 */ 

int run_get_private_key(const char* id, int id_len) {

	/* connect to the server first */
	connect_socket_server(SERVER_IP_ADDRESS, SERVER_LISTEN_PORT, &read_file, &write_file);

	/* arrange the private key request message */
	size_t m_len = (size_t)(PRIVATE_KEY_REQUEST_HEAD + id_len + AES_KEY_LEN);
	char *message = (char *)malloc(m_len);

	/* set the head */
	message[0] = PRIVATE_KEY_REQUEST_TYPE;
	*(int *)(message + 1) = id_len;

	/* copy the id */
	char *p = message + PRIVATE_KEY_REQUEST_HEAD;
	memcpy(p, id, (size_t)id_len);

	/* generate and copy the aes key */
	char key[AES_KEY_LEN];
	gen_random_key(key);
	p += id_len;
	memcpy(p, key, AES_KEY_LEN);

	/* set the context */
	memcpy(aes_key, key, AES_KEY_LEN);

	/* send the message */
	send_ibe(message, m_len, SERVER_ID, SERVER_ID_LEN, write_file);
	
	/* free the unused space */
	free(message);
	return 0;

end:
	free(message);
	return -1;

}
