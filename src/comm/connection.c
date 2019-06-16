/*****************************************************************************
Copyright: ...
File name: conenction.c
Description: 关于监听socket的建立和与服务器的连接的函数
Author: 王瑞凯
Version: ...
Date: 2019-06-16
History: ...
*****************************************************************************/


#include "base.h"
static long int current_client_id;

/**
 * create a listening socket
 * @return socket file descriptor or -1 for error
 */
int create_listening_socket(int listen_port)
{
	int listen_fd;
	struct sockaddr_in server_addr;

	if((listen_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	{
		fprintf(stderr, "can't create a listening socket\n");
		return -1;
	}
	
	bzero(&server_addr, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	server_addr.sin_port = htons(listen_port);

	if(bind(listen_fd, (SA *)&server_addr, sizeof(server_addr)) == -1)
	{
		fprintf(stderr, "can't bind listening socket\n");
		return -1;
	}

	if(listen(listen_fd, LISTEN_BACKLOG) == -1)
	{
		fprintf(stderr, "can't listen on listening socket\n");
		return -1;
	}
	
	return listen_fd;
}

int connect_socket_server(char* ip_addr, int port, FILE** read_file, FILE** write_file)
{
	int socket_fd;
	struct sockaddr_in server_addr;

	if((socket_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	{
		fprintf(stderr, "can't create client socket\n");
		return -1;
	}

	bzero(&server_addr, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(SERVER_LISTEN_PORT);
	inet_pton(AF_INET, ip_addr, &server_addr.sin_addr);
	
	if(connect(socket_fd, (SA *) &server_addr, sizeof(server_addr)) == -1)
	{
		fprintf(stderr, "can't connect to server socket\n");
		return -1;
	}

	if((*read_file = fdopen(socket_fd, "r+")) == NULL)
	{
		fprintf(stderr, "convertion from connected socket fd to FILE struct has error\n");
		return -1;
	}
	*write_file = *read_file;

	return 0;
}

int disconnect_socket_server(FILE* read_file, FILE* write_file)
{
	// socket is duplex, so read_file and write_file is the same file
	if(fclose(read_file) == EOF)
	{
		fprintf(stderr, "close the read file occurs an error: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

int run_listen_core(const char* server_id, FILE* read_file, FILE* write_file, FILE* log_file)
{
	// init the static variable
	current_client_id = -1;

	char crypto_type;
	do
	{	
		errno = 0; // clear the errno
		if(!fread(&crypto_type, sizeof(crypto_type), 1, read_file))
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
		switch (crypto_type)
		{
			case CRYPTO_IBE:
				if(handle_ibe(server_id, read_file, write_file) == -1)
				{
					fprintf(stderr, "handle IBE packet error\n");
					return -1;
				}
				break;
			case CRYPTO_AES:
				if(handle_aes() == -1)
				{
					fprintf(stderr, "handle AES packet error\n");
					return -1;
				}
				break;
		}
	} while(1);				// 客户端关闭之前一直执行

	return 0;
}

