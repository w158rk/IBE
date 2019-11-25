#ifndef COMM_LCL_H
#define COMM_LCL_H 

#ifdef __cplusplus 
extern "C"{
#endif

#include <sys/socket.h>
#include <stdio.h>

/* 
 * socket 监听与连接函数
 */
int create_listening_socket(int listen_port);
int connect_socket_server(char* ip_addr, int port, FILE** read_file, FILE** write_file);
int disconnect_socket_server(FILE* read_file, FILE* write_file);

/*****************************************************
 * 函数声明
 * ***************************************************/
/*
 * socket 包装函数
 */
int   Fgets(char* s, int size, FILE* stream);
ssize_t Write(int fd, const void *vptr, size_t n);
int     Accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);

/* 
 * 系统函数
 */
void sig_chld(int signo);
FILE* open_log_file();
#ifdef __cplusplus 
}
#endif


#endif