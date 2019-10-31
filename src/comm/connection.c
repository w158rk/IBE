/*****************************************************************************
Copyright: ...
File name: conenction.c
Description: 关于监听socket的建立和与服务器的连接的函数
Author: 王瑞凯
Version: ...
Date: 2019-06-16
History: ...
*****************************************************************************/


#include "depend.h"
#include "comm_lcl.h"
#include <config.h>

// 
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
	//server_addr.sin_port = htons(SERVER_LISTEN_PORT);
	server_addr.sin_port = htons(port);
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


// this function is from Unix Network Programming Section 3.9
ssize_t Write(int fd, const void *vptr, size_t n)
{
	size_t nleft;
	ssize_t nwritten;
	const char* ptr;

	ptr = vptr;
	nleft = n;
	while(nleft > 0)
	{
		if((nwritten = write(fd, ptr, nleft)) <= 0)
		{
			if(nwritten < 0 && errno == EINTR)
				nwritten = 0; // and call write() again
			else
				return -1; // error
		}

		nleft -= nwritten;
		ptr += nwritten;
	}

	return n;
}

int Accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	int connect_fd;
	if((connect_fd = accept(sockfd, addr, addrlen)) == -1)
	{
		if(errno == EINTR || errno == ECONNABORTED)
		{
			return Accept(sockfd, addr, addrlen);
		}
		else
		{
			return -1;
		}
	}
	
	return connect_fd;
}
