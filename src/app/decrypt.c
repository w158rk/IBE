/**
 * @file main.c
 * @brief the entrance of the whole system 
 * 
 * @author wrk
 * @date 2019.03.14
 */

#include "main.h"

const char pairing_file[] = "pairing.conf";

int main(int argc, char **argv)
{
    
    if(argc==1){
        printf("Please provide the ID!\n");
        return -1;
    }

    char *buff = (char *)malloc(BUFF_SIZE);

    char *ID = argv[1];   
    
    pairing_t pairing;   //The pair of bilinear map
    element_t Sid; 

    readFromFile(buff, pairing_file);
    pairing_init_set_str(pairing, buff);
    

    char private_file[SIZE] = "sk_";
    strcpy(private_file+3, ID);
    int test = readFromFile(buff, private_file);
    if(test==-1){
        printf("no private key exists\n");
        exit(1);
    }
    element_init_G1(Sid, pairing);
    element_from_bytes(Sid, buff);
    // element_printf("[main] Sid = %B\n", Sid);

    // read U
    element_t U;
    char ufile[SIZE] = "U_";
    strcpy(ufile+2, ID);
    test = readFromFile(buff, ufile);
    if(test==-1){
        printf("no U exists\n");
        exit(1);
    }
    element_init_G1(U, pairing);
    element_from_bytes(U, buff);
    // element_printf("[main] U = %B\n", U);

    // read V
    char vfile[SIZE] = "V_";
    strcpy(vfile+2, ID);
    char xor_result[SIZE]; //Sender XOR result---V
    memset(xor_result, 0, sizeof(char)*SIZE);
    test = readFromFile(buff, vfile);
    if(test==-1){
        printf("no V exists\n");
        exit(1);
    }
    strcpy(xor_result, buff);
    // printf("[main] %s\n" ,xor_result);

    // decrypt
    char xor_result_receiver[SIZE];  //Receiver XOR result
    memset(xor_result_receiver, 0, sizeof(char)*SIZE);    
    decryption(Sid, pairing, U, xor_result, xor_result_receiver);
    printf("\nThe recovery message digest is %s\n", xor_result_receiver);

    element_clear(Sid);
    pairing_clear(pairing);
        
    return 0;
}