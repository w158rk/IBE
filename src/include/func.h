
/**!
 * @file func.h
 * @author Wang Ruikai 
 * @date Oct 10th, 2019 
 * @brief This file includes the complex functions
 */

#include <ds.h>

#ifndef  FUNC_H
#define FUNC_H

/****************************************************************
 * functions for complex purposes
 **************************************************************/
/**!
 * @brief get the private key for a user 
 * @param[in] id ID of the user who are to apply for the private key 
 * @param[in] id_len the length of the ID
 */
int run_get_private_key(const char* id, int id_len);


/**!
 * @brief run the user interface. Generally, it receives a request from the 
 *      the user and do something 
 * @param entity_id the id of the user 
 * @param id_len the length of the id 
 * @return -1 when something wrong, 0 when no errors
 */
int socket_interface_run(const char* entity_id, int id_len);

int socket_main(ID *id_name,  int port);

#endif