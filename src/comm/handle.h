/**!
 * @file handle.h
 * @author Wang Ruikai 
 * @date July 18th, 2019 
 * @brief plaintext handler functions 
 */


#ifndef HANDLE_H 
#define HANDLE_H 

#include <stdlib.h>
#include <stdio.h>

/****************************************************************
 * functions to respond to the plaintext
 **************************************************************/

/**!
 * @brief handle the decrypted messages 
 * @param[in] m the decrypted message 
 * @param[in] m_len the length of the message 
 * @param[in] write_file the socket file where the user send something 
 * @return 0 if no error, -1 if something wrong
 */
int handle_message(unsigned char *m, size_t m_len, FILE *write_file) ;

/**!
 * @brief handle the plain text, generally, print the readable text 
 * @param[in] m the decrypted message 
 * @param[in] m_len the length of the message 
 * @param[in] write_file the socket file where the user send something 
 * @return 0 if no error, -1 if something wrong
 */
int handle_plaintext(unsigned char *m, size_t m_len, FILE *write_file) ;

/**!
 * @brief handle the private key request, generally, calculate the private key 
 *          and send it out by the secret channel 
 * @param[in] m the decrypted message 
 * @param[in] m_len the length of the message 
 * @param[in] write_file the socket file where the user send something 
 * @return 0 if no error, -1 if something wrong
 */
int handle_private_key_request(unsigned char *m, size_t m_len, FILE *write_file) ;

/**!
 * @brief handle the private key response, generally, get the private key and 
 *          store it locally 
 * @param[in] m the decrypted message 
 * @param[in] m_len the length of the message 
 * @param[in] write_file the socket file where the user send something 
 * @return 0 if no error, -1 if something wrong
 */
int handle_private_key_response(unsigned char *m, size_t m_len, FILE *write_file) ;


#endif