/**
 * This file contains wrapper functions and facility functions used  in client and server
 */

#include "client_server.h"

/*
 * this function is a wrapper function of c library function fgets, the purpose is to handle the error caused by eof and EINTR
 * this function should be used when read end may not be available
 * when you know there is a opened read end, you should use read_line function
 */
char* Fgets(char* s, int size, FILE* stream)
{
	char* fgets_result = fgets(s, size, stream);
	if((fgets_result == NULL) && !feof(stream) && (errno != EINTR))
	{
		return NULL;
	}
	else if(fgets_result == NULL && feof(stream)) // read end is not available
	{
		sleep(1);
		return Fgets(s, size, stream);
	}
	else if(fgets_result == NULL && errno == EINTR)
	{
		return Fgets(s, size, stream);
	}
	else
	{
		return fgets_result;
	}
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

void remove_ending_line_break(char* string)
{
	string[strlen(string) - 1] = '\0';
}	

/*
 * this function should be used when you know there is an opened read end
 * this function will deal with the eof problem which means the read end closed abruptly
 */
char* read_line(char* line, int size, FILE* stream, bool exist_on_fail)
{
	char* read_result = fgets(line, size, stream);	
	if(exist_on_fail)
	{
		if(read_result == NULL)
		{
			fprintf(stderr, "can't read information from another end: %s\n", strerror(errno));
			exit(-1);
		}
	}
	
	return read_result;
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
