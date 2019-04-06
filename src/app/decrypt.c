/**
 * @file main.c
 * @brief the entrance of the whole system 
 * 
 * args:
 *          1   :   m
 *          2   :   sk
 *          3   :   u
 *          4   :   v
 * 
 * @author wrk
 * @date 2019.03.14
 */

#include "main.h"
# define DEBUG
const char pairing_file[] = "pairing.conf";

int main(int argc, char **argv)
{
    
    if(argc!=5){
        printf("4 arguments needed!\n");
        return -1;
    }

    char *buff = (char *)malloc(BUFF_SIZE);

    pairing_t pairing;   //The pair of bilinear map
    element_t Sid; 

    readFromFile(buff, pairing_file);
    pairing_init_set_str(pairing, buff);
    

    char *private_file = argv[2];
    readFromFile(buff, private_file);
    element_init_G1(Sid, pairing);
    element_from_bytes(Sid, buff);
    // element_printf("[main] Sid = %B\n", Sid);

    // read U
    element_t U;
    char *ufile = argv[3];
    readFromFile(buff, ufile);
    element_init_G1(U, pairing);
    element_from_bytes(U, buff);
    element_printf("[main] U = %B\n", U);

    // read V
    char *vfile = argv[4];
    char xor_result[SIZE]; //Sender XOR result---V
    memset(xor_result, 0, sizeof(char)*SIZE);
    readFromFile(buff, vfile);
    strcpy(xor_result, buff);
    printf("[main] %s\n" ,xor_result);

    // decrypt
    char xor_result_receiver[SIZE];  //Receiver XOR result
    memset(xor_result_receiver, 0, sizeof(char)*SIZE);    
    decryption(Sid, pairing, U, xor_result, xor_result_receiver);
    char *mfile = argv[1];
    #ifdef DEBUG 
    printf("[decrypt] out put to %s \n", mfile);
    #endif
    output_str(mfile, xor_result_receiver);

    element_clear(Sid);
    pairing_clear(pairing);
        
    return 0;
}