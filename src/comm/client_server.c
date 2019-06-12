/**
 * This file contains wrapper functions and facility functions used  in client and server
 */

#include "client_server.h"
#include "../crypto/crypto.h"

/*
 * this function is a wrapper function of c library function fgets, the purpose is to handle the error caused by eof and EINTR
 * this function should be used when read end may not be available
 * when you know there is a opened read end, you should use read_line function
 */
// char* Fgets(char* s, int size, FILE* stream)
// {
// 	char* fgets_result = fgets(s, size, stream);
// 	if((fgets_result == NULL) && !feof(stream) && (errno != EINTR))
// 	{
// 		return NULL;
// 	}
// 	else if(fgets_result == NULL && feof(stream)) // read end is not available
// 	{
// 		sleep(1);
// 		return Fgets(s, size, stream);
// 	}
// 	else if(fgets_result == NULL && errno == EINTR)
// 	{
// 		return Fgets(s, size, stream);
// 	}
// 	else
// 	{
// 		return fgets_result;
// 	}
// }

int Fgets(char* s, int size, FILE* stream)
{
	char* fgets_result = fgets(s, size, stream);
	if((fgets_result == NULL) && !feof(stream) && (errno != EINTR))
	{
		return -1;
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
		s = fgets_result;
		return 0;
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
// char* read_line(char* line, int size, FILE* stream, bool exist_on_fail)
// {
// 	char* read_result = fgets(line, size, stream);	
// 	if(exist_on_fail)
// 	{
// 		if(read_result == NULL)
// 		{
// 			fprintf(stderr, "can't read information from another end: %s\n", strerror(errno));
// 			exit(-1);
// 		}
// 	}
	
// 	return read_result;
// }

int read_line(char* line, int size, FILE* stream, bool exist_on_fail)
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

	line = read_result;
	return 0;
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

int handle_ibe(char *id) {
	// 1. 获取密钥、密文长度、密文 
	// 2. 解密后解析明文，触发相关处理函数
	char len_str[5] = {'\0'};				// 长度
	unsigned int c_len;
	char *c;
	if (-1 == fread(len_str, sizeof(char), 4, read_file)) {
		fprintf(stderr, "read IBE cipher length error\n");
		return -1;
	}

	// 字符转整数 - 网络序转机器序 
	c_len = stoi(len_str);
	c_len = ntohl(c_len);
	c = (char *) malloc(c_len);

	// read cipher
	if (-1 == fread(c, sizeof(char), c_len, read_file)) {
		fprintf(stderr, "read IBE cipher error with lengh %d\n", c_len);
		return -1;
	}

	// make the private key filename 
	char temp[20] = "sk_";
	int id_len = strlen(id)>16 ? 16 : strlen(id);  
	memcpy(temp, id, id_len);
	char *sk_filename = strcat(temp, ".conf");

	// read private key
	SM9PrivateKey *sk = SM9PrivateKey_new();
	if (-1 == get_sk_fp(sk_filename, sk)) {
		fprintf(stderr, "read IBE private key error with filename : %s\n", sk_filename);
		return -1;
	}

	// decrypt
	char *m[BUFFER_SIZE];
	int m_len;
	if (-1 == sm9_decrypt(c, c_len, m, &m_len, sk)) {
		fprintf(stderr, "IBE decrypt fails\n");
		return -1;
	}

	printf("decrypted text : %s\n", m);
	// do something else 
}