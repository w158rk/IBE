
#ifndef COMM_H 
#define COMM_H 

#include <ds.h>
int socket_main(ID *id_name, int port);
int run_listen_core(const char* entity_id,int entity_id_len, FILE* read_file, FILE* write_file, FILE* log_file);
/**!
 * @brief run the user interface. Generally, it receives a request from the 
 *      the user and do something 
 * @param entity_id the id of the user 
 * @param id_len the length of the id 
 * @return -1 when something wrong, 0 when no errors
 */
int socket_interface_run(ID *id_name);

void *socket_listener_run(void *args);

#endif