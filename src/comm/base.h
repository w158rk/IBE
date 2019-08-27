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
#include <ctx.h>

#define __SOCKET_MODE__

// #define SA                      struct sockaddr

#define SYSTEM_LOG "/tmp/ibe_log"
#define NUM_THREADS 4


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
int run_listen_core(const char* entity_id,int entity_id_len, FILE* read_file, FILE* write_file, FILE* log_file);
void *socket_listener_run(void *args);
void sig_chld(int signo);

/****************************************************************
 * functions to convert between the cipher and the plaintext
 **************************************************************/

/**!
 * @brief receive the IBE packet and decrypt it into plain message
 * @param[out] m the decrypted message
 * @param[out] m_len the length of the decrypted message
 * @param[in] id the id of the user 
 * @param[in] read_file socket file where the cipher comes in
 * @return 0 if no error, -1 if something wrong
 */
int receive_ibe(unsigned char *m, size_t *m_len, 
                 const char *id, FILE *read_file);

/**!
 * @brief make a IBE packet for the given message and send it out 
 * @param[in] m the message to send 
 * @param[in] m_len the length of the message 
 * @param[in] id the target id 
 * @param[in] id_len the length of the target id
 * @param[in] write_file the socket file where to send information 
 * @return 0 if no error, -1 if something wrong
 */
int send_ibe(unsigned char *m, size_t m_len, const char* id, 
                size_t id_len, FILE *write_file);

/**!
 * @brief get the AES packet and decrypt it into plain message 
 * @param m the decrypted message 
 * @param m_len the length of the decrypted message 
 * @param read_file the socket file where the user receives information 
 * @param aes_key the key for decryption 
 * return 0 if no error, -1 if something wrong 
 */ 
int receive_aes(unsigned char *m, size_t *m_len, 
                FILE *read_file, unsigned char* aes_key); 

/**!
 * @brief make a AES packet for the given message and send it out 
 * @param[in] m the message to send 
 * @param[in] m_len the length of the message 
 * @param[in] key the aes key for encrypt 
 * @param[in] write_file the socket file where to send information 
 * @return 0 if no error, -1 if something wrong
 */
int send_aes(unsigned char *m, size_t m_len, 
             const char* key, FILE *write_file);




/****************************************************************
 * functions for complex purposes
 **************************************************************/
/**!
 * @brief get the private key for a user 
 * @param[in] id ID of the user who are to apply for the private key 
 * @param[in] id_len the length of the ID
 */
int run_get_private_key(const char* id, int id_len);

/* 
 * 系统函数
 */
FILE* open_log_file();

/**!
 * @brief run the user interface. Generally, it receives a request from the 
 *      the user and do something 
 * @param entity_id the id of the user 
 * @param id_len the length of the id 
 * @return -1 when something wrong, 0 when no errors
 */
int socket_interface_run(const char* entity_id, int id_len);

#endif
