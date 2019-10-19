/**!
 * @file base.h
 * @author Wang Ruikai 
 * @date July 14th, 2019 
 * @brief This file contains the data, macro common to both client and server
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

#define __SOCKET_MODE__

// #define SA                      struct sockaddr



/*****************************************************
 * 协议相关参数
 * ***************************************************/
// #define CRYPTO_IBE 					  	0
// #define CRYPTO_AES 						1
// #define CRYPTO_HEAD_LEN 				24
/*  
 * IBE parameters
 */
// #define IBE_HEAD_LEN                    5
/*
 * AES parameteres 
 */
// #define AES_HEAD_LEN                    21
/*
 *通信参数
 */
// #define SUCCESS                       0
// #define FAILURE                       1
// #define ESTABLISH_CONNECTION_REQUEST  2
// #define ESTABLISH_CONNECTION_RESPONSE 3
// #define ESTABLISH_CONNECTION_ACK      4


/*****************************************************
 * 类型定义
 * ***************************************************/
typedef struct sockaddr SA;



#endif
