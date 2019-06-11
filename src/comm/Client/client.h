#ifndef CLIENT_H
#define CLIENT_H

#include <stdio.h>

int connect_fifo_server(char* server_public_fifo_name, FILE** read_file, FILE** write_file);
int disconnect_fifo_server(FILE* read_file, FILE* write_file);

int connect_socket_server(char* ip_addr, int port, FILE** read_file, FILE** write_file);
int disconnect_socket_server(FILE* read_file, FILE* write_file);

int run_client_core(FILE* read_file, FILE* write_file);
#endif
