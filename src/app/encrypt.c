/**
 * @file main.c
 * @brief the entrance of the whole system 
 * 
 * @author wrk
 * @date 2019.03.14
 */

#include "main.h"

#define STRINGSIZE 200
const char pairing_file[] = "pairing.conf";
const char public_file[] = "public.conf";
const char point_file[] = "point.conf";

int main(int argc, char **argv)
{
    if(argc==0){
        printf("Please provide the destination ID!\n");
        return -1;
    }

    char *buff = NULL;

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



    readFromFile(&buff, pairing_file);
    pairing_init_set_str(pairing, buff);
    free(buff);

    readFromFile(&buff, public_file);
    element_init_G1(Ppub, pairing);
    element_set_str(Ppub, buff, BASE);
    free(buff);

    readFromFile(&buff, point_file);
    element_init_G1(P, pairing);
    element_set_str(P, buff, BASE);
    free(buff);

    
    mpz_t messagehash;
    mpz_init(messagehash);
    
    printf("##########ENCRPTION##########\n");
    printf("\nPlase enter the message to encrypt:");
    scanf("%[ a-zA-Z0-9+*-!.,&*@{}$#]", message);
    getchar();
    printf("The original message=%s", message);
    
    sha_fun(message, shamessage);   //Get the message digest
    printf("\nThe message hash=%s\n", shamessage);
    
    element_init_G1(U, pairing);
    encryption(shamessage, destination, P, Ppub, U, xor_result, pairing);
    printf("Send <U,V> to the receiver!\n");
    
    element_clear(P);
    element_clear(Ppub);
    element_clear(U);
    pairing_clear(pairing);
    
  return 0;
}