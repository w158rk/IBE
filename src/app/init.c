/**
 * @file main.c
 * @brief the entrance of the whole system 
 * 
 * @author wrk
 * @date 2019.03.14
 */

#include "main.h"

int main(int argc, char **argv)
{
    
    char qbits[5] = "512";
    char rbits[5] = "160";
    // char ID[SIZE] = argv[0]   //User ID
        
    pairing_t pairing;   //The pair of bilinear map
        
    element_t P, Ppub, s, U, Qid, Sid;
    mpz_t messagehash;
    mpz_init(messagehash);

    printf("beign to set up system!\n");

    setup_sys(atoi(rbits), atoi(qbits), P, Ppub, pairing, s);
    printf("System parameters have been set!\n");

    return 0;
}