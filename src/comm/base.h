/**
 * This file contains the data, macro common to both client and server
 */

#ifndef BASE_H
#define BASE_H

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "config.h"

#define __SOCKET_MODE__

// #define SA                      struct sockaddr

#define SYSTEM_LOG "/tmp/ibe_log"
#define NUM_THREADS 4


/*****************************************************
 * 协议相关参数
 * ***************************************************/
#define CRYPTO_IBE 					  	0
#define CRYPTO_AES 						1
#define CRYPTO_HEAD_LEN 				24
/*  
 * IBE parameters
 */
#define IBE_HEAD_LEN                    5
/*
 * AES parameteres 
 */
#define AES_HEAD_LEN                    21
#define AES_KEY_LEN 					32 
#define AES_IV_LEN 					16 
/*
 *通信参数
 */
// #define SUCCESS                       0
// #define FAILURE                       1
#define ESTABLISH_CONNECTION_REQUEST  2
#define ESTABLISH_CONNECTION_RESPONSE 3
#define ESTABLISH_CONNECTION_ACK      4


/*****************************************************
 * 类型定义
 * ***************************************************/
typedef struct sockaddr SA;

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
 * socket 监听与连接函数
 */
int create_listening_socket(int listen_port);
int connect_socket_server(char* ip_addr, int port, FILE** read_file, FILE** write_file);
int disconnect_socket_server(FILE* read_file, FILE* write_file);
int run_listen_core(const char* server_id, FILE* read_file, FILE* write_file, FILE* log_file);
void *socket_listener_run(void *args);
void sig_chld(int signo);

/*
 * 加密数据包处理函数
 */
int handle_ibe(const char *id, FILE *read_file, FILE *write_file);
int handle_aes();

/* 
 * 功能函数
 */
int run_get_private_key(const char* id, int id_len);

/* 
 * 系统函数
 */
FILE* open_log_file();
int socket_interface_run(const char* entity_id, int id_len);

#endif
