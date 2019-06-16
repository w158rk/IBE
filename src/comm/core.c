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
// #define __DEBUG__


/* 
 * internal functions
 */ 

int socket_interface_run(const char* entity_id, int id_len) {
	
	printf("What do you want to do? %s\n", entity_id);
	printf("Choose from :\n");
	printf("\t1. Extract your Private Key\n");
	
	int choise;
	scanf("%d", &choise);
	switch (choise) {
		case 1/* constant-expression */:
			/* code */
			if (-1 == run_get_private_key(entity_id, id_len)) {
				return -1;
			}			
			break;
		default:
			break;
	}

	return 0;
}

void *socket_listener_run(void *args)
{
	char *error_sig = (char *)args;
	char entity_id[MAX_ID_SIZE];
	memcpy(entity_id, (char *)args+8, MAX_ID_SIZE);

	int listen_fd, connect_fd;
	struct sockaddr_in client_addr;
	socklen_t client_len;

	int *p = (int *)args+1;			// 读取监听端口
	int listen_port = *p;

	if((listen_fd = create_listening_socket(listen_port)) == -1)
	{
		fprintf(stderr, "can't create listening socket\n");
		*error_sig = -1;
	}
	
	FILE* log_file;
	log_file = open_log_file();

	bool main_server_has_error = false;

	#ifdef __DEBUG__
	fprintf(stdout, "start listening\n");
	#endif

	if(signal(SIGCHLD, sig_chld) == SIG_ERR)					// 锁
	{
		fprintf(stderr, "can't bind signal handler\n");
		main_server_has_error = true;
	}
	
	while(main_server_has_error == false)					// 业务
	{
		client_len = sizeof(client_addr);
		if((connect_fd = Accept(listen_fd, (SA*)&client_addr, &client_len)) == -1)				// 建立连接
		{
			fprintf(stderr, "accept error\n");
			main_server_has_error = true;
			break;
		}

		if(fork() == 0) // child process
		{				// 监听进程
			int child_server_status = 0;

			FILE* read_file;
			FILE* write_file;

			if(close(listen_fd) == -1)
			{
				fprintf(stderr, "server child close listening socket error\n");
				child_server_status = -1;
			}
			
			if((read_file = fdopen(connect_fd, "r+")) == NULL)
			{
				fprintf(stderr, "convertion from connected socket fd to FILE struct has error\n");
				close(connect_fd);
				child_server_status = -1;
			}
			else
			{
				write_file = read_file; // socket is duplex

				#ifdef __DEBUG__
				fprintf(stdout, "establish client server socket connection\n");
				#endif

				if(run_listen_core(entity_id, read_file, write_file, open_log_file()) == -1)
				{
					// 业务
					fprintf(stderr, "server core has error\n");
					child_server_status = -1;
				}

				//disconnect client socket is duplex, so read_file and write_file is the same file
				if(fclose(read_file) == EOF)
				{
					fprintf(stderr, "close the read file occurs an error\n");
					child_server_status = -1;
				}

				if(log_file != NULL)
				{
					fclose(log_file);
				}
			}
			
			// return child_server_status;
		}

		if(close(connect_fd) == -1)
		{
			fprintf(stderr, "server close connected socket error\n");
			*error_sig = -1;
		}
	}

	// you go here means you have something wrong
	if(close(listen_fd) == -1)
	{
		fprintf(stderr, "server child close listening socket error\n");
	}
	if(log_file != NULL)
	{
		fclose(log_file);
	}

	*error_sig = -1;
}

int run_get_private_key(const char* id, int id_len) {
	FILE *read_file;
	FILE *write_file; 
	connect_socket_server(SERVER_IP_ADDRESS, SERVER_LISTEN_PORT, &read_file, &write_file);

	char server_id[MAX_ID_SIZE] = SERVER_ID;
	// printf("请输入服务器ID\n");
	// scanf("%s", server_id);

	// 做私钥请求的网络包 
	char *message = (char *)malloc(BUFFER_SIZE);

	// id
	char *p = message;
	memcpy(p, id, MAX_ID_SIZE);
	p += MAX_ID_SIZE;

	// AES 密钥
	char key[AES_KEY_LEN];
	gen_random_key(key);
	memcpy(p, key, AES_KEY_LEN);

	// 加密 
	char c[BUFFER_SIZE];
	int c_len;

	SM9PublicParameters *mpk = SM9PublicParameters_new();

	if (-1 == get_mpk_fp(MPK_FILENAME, mpk)) {
		fprintf(stderr, "read mpk fails\n");
		return -1;
	}

	if (-1 == sm9_encrypt(message, MAX_ID_SIZE+AES_KEY_LEN, c, &c_len, mpk, server_id, id_len) ) {
		fprintf(stderr, "encrypt error\n");
		return -1;
	}

	// 做包，加头 
	int packet_len = CRYPTO_HEAD_LEN + c_len;
	char *packet = (char *)malloc(packet_len);
	memcpy(packet+CRYPTO_HEAD_LEN, c, c_len);
	fprintf(stderr, "[debug] c len : %d\n", c_len);
	c_len = htonl(c_len);
	char *len_str = (char *)&c_len;
	memcpy(packet+1, len_str, 4);
	packet[0] = CRYPTO_IBE;

	// 发送 
	Write(fileno(write_file), packet, packet_len);
}

void sig_chld(int signo)
{
	pid_t pid;
	int stat;
	
	while((pid = waitpid(-1, &stat, WNOHANG)) > 0)
	{
		#ifdef __DEBUG__
		printf("child %d terminated\n", pid);
		#endif
	}
	
	return;
}

FILE* open_log_file()
{
	FILE* log_file;
	if((log_file = fopen(SYSTEM_LOG, "a")) == NULL)
	{
		fprintf(stderr, "can't open log file: %s\n", strerror(errno));
	}
	
	return log_file;
}


