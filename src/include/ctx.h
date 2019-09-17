/**!
 * @file ctx.h 
 * @author Wang Ruikai 
 * @date July 18th, 2019 
 * @brief the context where the program runs
 */

#ifndef CTX_H
#define CTX_H 

#include <config.h>
#include <crypto.h>


unsigned char user_id[MAX_ID_LEN];
unsigned char aes_key[AES_KEY_LEN];
unsigned char sm4_key[SM4_KEY_LEN];

FILE *read_file;
FILE *write_file; 



#endif