#ifndef SERVER_H
#define SERVER_H
int create_listening_fifo(char* server_public_fifo_name, FILE** read_file);
int close_listening_fifo(FILE* read_file);
int establish_client_server_fifo_connection(pid_t client_pid, FILE** read_file, FILE** write_file);

int create_listening_socket(int listen_port);

int socket_main(const char* entity_id, int id_len, int port);
int run_server_core(const char* server_id, FILE* read_file, FILE* write_file, FILE* log_file);
#endif
