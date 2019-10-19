
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
int run_get_private_key(const char* id, int id_len, ID *father_node);

int run_send_message(const char* id, int id_len, char* ip, int port, char* dest_id);


#endif