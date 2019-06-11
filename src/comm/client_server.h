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

#define BUFFER_SIZE             1024
#define MAX_STRING              256
#define SERVER_PORT             5001
#define LISTEN_BACKLOG          50
#define SERVER_IP_ADDRESS       "127.0.0.1"
#define SERVER_PUBLIC_FIFO_NAME "/tmp/server_public_fifo"
#define SA                      struct sockaddr

#define SUCCESS                       0
#define FAILURE                       1
#define ESTABLISH_CONNECTION_REQUEST  2
#define ESTABLISH_CONNECTION_RESPONSE 3
#define ESTABLISH_CONNECTION_ACK      4
#define REGISTER_REQUEST              5
#define REGISTER_RESPONSE             6
#define FINISH_REQUEST                7
#define FINISH_ACK                    10
#define LOGIN_REQUEST                 8
#define LOGIN_RESPONSE                9
#define QUERY_BY_STATION_REQUEST      10
#define QUERY_BY_STATION_RESPONSE     11
#define ORDER_REQUEST                 12
#define ORDER_RESPONSE                13
#define REFUND_REQUEST                14
#define REFUND_RESPONSE               15
#define QUERY_BOOKED_TICKET_REQUEST   16
#define QUERY_BOOKED_TICKET_RESPONSE  17

typedef struct
{
	char train_name[MAX_STRING];
	char start_station[MAX_STRING];
	char end_station[MAX_STRING];
	char start_time[MAX_STRING];
	int  cost_time;
	int  money;
}query_by_station_result;

typedef struct
{
	long int ticket_id;
	char train_name[MAX_STRING];
	char start_station[MAX_STRING];
	char end_station[MAX_STRING];
	char departure_time[MAX_STRING];
}query_booked_ticket_result;

char*   Fgets(char* s, int size, FILE* stream);
ssize_t Write(int fd, const void *vptr, size_t n);
int     Accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
void    remove_ending_line_break(char* string);
char*   read_line(char* line, int size, FILE* stream, bool exist_on_fail);
#endif
