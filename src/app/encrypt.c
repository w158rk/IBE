/**
 * @file main.c
 * @brief the entrance of the whole system 
 * 
 * @author wrk
 * @date 2019.03.14
 */

#include "main.h"

#define STRINGSIZE 200



int main(int argc, char **argv)
{

    const char pairing_file[] = "pairing.conf";
    const char public_file[] = "public.conf";
    const char point_file[] = "point.conf";
    
    if(argc==1){
        printf("Please provide the destination ID!\n");
        return -1;
    } if(argc==3) {
        printf("[length] %d\n", argc);

        char *buff = (char *)malloc(BUFF_SIZE);

        char *destination = argv[1];   //ID of receiver
        char *message = argv[2];             //User message
        char shamessage[SIZE];           //The input message digest(sha1 result)
        
        char xor_result[SIZE]; //Sender XOR result---V
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
        encryption(message, destination, P, Ppub, U, xor_result, pairing);
        printf("Send <U,V> to the receiver!\n");

        char ufile[SIZE] = "U_";
        strcpy(ufile+2, destination);
        output_par(ufile, U);

        char vfile[SIZE] = "V_";
        strcpy(vfile+2, destination);
        output_str(vfile, xor_result);
        
        element_clear(P);
        element_clear(Ppub);
        element_clear(U);
        pairing_clear(pairing);
    }
    else {
        char *buff = (char *)malloc(BUFF_SIZE);

        char *destination = argv[1];   //ID of receiver
        char message[SIZE];             //User message
        char shamessage[SIZE];           //The input message digest(sha1 result)
        
        char xor_result[SIZE]; //Sender XOR result---V
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
        
        //element_printf("[main] P = %B\n", P);

        // mpz_t messagehash;
        // mpz_init(messagehash);
        
        //printf("##########ENCRPTION##########\n");
        //printf("\nPlase enter the message to encrypt:");
        scanf("%[ a-zA-Z0-9+*-!.,&*@{}$#']", message);
        getchar();
        //printf("The original message=%s\n", message);
        
        element_init_G1(U, pairing);
        encryption(message, destination, P, Ppub, U, xor_result, pairing);
        //element_printf("[main] U = %B\n", U);
        printf("Send <U,V> to the receiver!\n");

        // //element_printf("%B\n", U);
        char ufile[SIZE] = "U_";
        strcpy(ufile+2, destination);
        output_par(ufile, U);

        char vfile[SIZE] = "V_";
        strcpy(vfile+2, destination);
        output_str(vfile, xor_result);
        
        element_clear(P);
        element_clear(Ppub);
        element_clear(U);
        pairing_clear(pairing);
    }

 
    
  return 0;
}