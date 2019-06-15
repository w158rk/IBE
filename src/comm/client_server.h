/**
 * This file contains the data, macro common to both client and server
 */

#ifndef CLIENT_SERVER_H
#define CLIENT_SERVER_H

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

#define BUFFER_SIZE             1024
#define MAX_ID_SIZE				20
#define MAX_STRING              256
#define LISTEN_BACKLOG          50
#define SERVER_PUBLIC_FIFO_NAME "/tmp/server_public_fifo"
// #define SA                      struct sockaddr

#define SERVER_ID              "Server"
#define SERVER_ID_LEN           6
#define SERVER_IP_ADDRESS       "127.0.0.1"
#define SERVER_LISTEN_PORT      5001
#define SERVER_RUN_PORT         5002

#define CLIENT_ID              "Client"
#define CLIENT_ID_LEN           6
#define CLEINT_IP_ADDRESS       "127.0.0.1"
#define CLIENT_LISTEN_PORT      16001
#define CLIENT_RUN_PORT         16002


#define CRYPTO_IBE 					  	0
#define CRYPTO_AES 						1
#define CRYPTO_HEAD_LEN 				24

/* IBE 
 * parameters
 */

#define IBE_HEAD_LEN                    5


/*
 * AES 
 * parameteres 
 */
#define AES_HEAD_LEN                    21
#define AES_KEY_LEN 					32 
#define AES_IV_LEN 					16 


// #define SUCCESS                       0
// #define FAILURE                       1
#define ESTABLISH_CONNECTION_REQUEST  2
#define ESTABLISH_CONNECTION_RESPONSE 3
#define ESTABLISH_CONNECTION_ACK      4
// #define REGISTER_REQUEST              5
// #define REGISTER_RESPONSE             6
// #define FINISH_REQUEST                7
// #define FINISH_ACK                    10
// #define LOGIN_REQUEST                 8
// #define LOGIN_RESPONSE                9
// #define QUERY_BY_STATION_REQUEST      10
// #define QUERY_BY_STATION_RESPONSE     11
// #define ORDER_REQUEST                 12
// #define ORDER_RESPONSE                13
// #define REFUND_REQUEST                14
// #define REFUND_RESPONSE               15
// #define QUERY_BOOKED_TICKET_REQUEST   16
// #define QUERY_BOOKED_TICKET_RESPONSE  17

typedef struct sockaddr SA;

int   Fgets(char* s, int size, FILE* stream);
ssize_t Write(int fd, const void *vptr, size_t n);
int     Accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
void    remove_ending_line_break(char* string);
int   read_line(char* line, int size, FILE* stream, bool exist_on_fail);

int connect_socket_server(char* ip_addr, int port, FILE** read_file, FILE** write_file);
int disconnect_socket_server(FILE* read_file, FILE* write_file);

int handle_ibe(const char *id, FILE *read_file, FILE *write_file);
int handle_aes();
#endif
