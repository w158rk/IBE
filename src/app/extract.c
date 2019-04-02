/**
 * @file main.c
 * @brief the entrance of the whole system 
 * 
 * @author wrk
 * @date 2019.03.14
 */

#include "main.h"

const char pairing_file[] = "pairing.conf";
const char public_file[] = "public.conf";
const char point_file[] = "point.conf";
const char private_file[] = "private.conf";

int main(int argc, char **argv)
{
    
    if(argc==1){
        printf("Please provide the ID!\n");
        return -1;
    }

    char *buff = (char *)malloc(BUFF_SIZE);

    char *ID = argv[1];   
    
    pairing_t pairing;   //The pair of bilinear map
    element_t s, Sid; 

    readFromFile(buff, pairing_file);
    pairing_init_set_str(pairing, buff);

    readFromFile(buff, private_file);
    element_init_Zr(s, pairing);
    element_from_bytes(s, buff);

    get_private_key(ID, pairing, s, Sid);
    
    char filename[SIZE] = "sk_";
    strcpy(filename+3, ID);
    output_par(filename, Sid);

    element_clear(Sid);
    element_clear(s);
    pairing_clear(pairing);
        
    return 0;
}