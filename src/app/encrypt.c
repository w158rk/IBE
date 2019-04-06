/**
 * @author wrk
 * @date 2019.03.14
 * args:
 *          0   :   m
 *          1   :   id
 *          2   :   u
 *          3   :   v
 */

#include "main.h"

#define STRINGSIZE 200



int main(int argc, char **argv)
{

    const char pairing_file[] = "pairing.conf";
    const char public_file[] = "public.conf";
    const char point_file[] = "point.conf";
    
    if(argc!=5){
        printf("4 arguments needed!\n");
        return -1;
    } else {
        // printf("[length] %d\n", argc);

        char *buff = (char *)malloc(BUFF_SIZE);

        char *mfile = argv[1];             //User message
        char *dfile = argv[2];   //ID of receiver
        
        char message[SIZE];           //The input message 
        char ID[SIZE];
        readFromFile(message, mfile);
        readFromFile(ID, dfile);

        char xor_result[SIZE];          //Sender XOR result---V
        char xor_result_receiver[SIZE];  //Receiver XOR result
        memset(xor_result, 0, sizeof(char)*SIZE);
        memset(xor_result_receiver, 0, sizeof(char)*SIZE);
        
        pairing_t pairing;   //The pair of bilinear map
        element_t P; 
        element_t Ppub, U;

        int length = readFromFile(buff, pairing_file);
        pairing_init_set_buf(pairing, buff, length);

        readFromFile(buff, public_file);
        element_init_G1(Ppub, pairing);
        element_from_bytes(Ppub, buff);

        readFromFile(buff, point_file);
        element_init_G1(P, pairing);
        element_from_bytes(P, buff);

        element_init_G1(U, pairing);
        encryption(message, ID, P, Ppub, U, xor_result, pairing);

        char *ufile = argv[3];
        output_par(ufile, U);

        char *vfile = argv[4];
        output_str(vfile, xor_result);
        
        element_clear(P);
        element_clear(Ppub);
        element_clear(U);
        pairing_clear(pairing);
    }
    
    return 0;
}