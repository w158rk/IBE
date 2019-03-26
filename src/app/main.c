/**
 * @file main.c
 * @brief the entrance of the whole system 
 * 
 * @author wrk
 * @date 2019.03.14
 */

#include "main.h"

int main()
{
    
  char qbits[5] = "512";
  char rbits[5] = "160"; 
  char ID[SIZE] = "wrk";   //User ID
  char message[SIZE] = "wrk";   //User message
  char shamessage[SIZE]; //The input message digest(sha1 result)
    
  char xor_result[SIZE]; //Sender XOR result---V
  char xor_result_receiver[SIZE];  //Receiver XOR result
  memset(xor_result, 0, sizeof(char)*SIZE);
  memset(xor_result_receiver, 0, sizeof(char)*SIZE);
    
    
  pairing_t pairing;   //The pair of bilinear map
    
  element_t P, Ppub, s, U, Qid, Sid;
  mpz_t messagehash;
  mpz_init(messagehash);
    
  printf("\n############SETUP############\n");
  setup_sys(atoi(rbits), atoi(qbits), P, Ppub, pairing, s);
  printf("System parameters have been set!\n");

    #ifdef DEVELOP 
    element_printf("s = %B\n", s);
    #endif 

    element_printf("P = %B\n", P);
    element_printf("Ppub = %B\n", Ppub);
    
    
    printf("###########EXTRACT###########\n");
    element_init_G1(Qid, pairing);
    element_init_G1(Sid, pairing);
    get_private_key(ID, pairing, s, Sid);
    get_public_key(ID, pairing, Qid);

    #ifdef DEVELOP 
    element_printf("Sid = %B\n", Sid);
    element_printf("Qid = %B\n", Qid);
    #endif 

    printf("##########ENCRPTION##########\n");
    printf("The original message=%s", message);
    
    sha_fun(message, shamessage);   //Get the message digest
    printf("\nThe message hash=%s\n", shamessage);
    
    element_init_G1(U, pairing);
    encryption(shamessage, ID, P, Ppub, U, xor_result, pairing);
    printf("Send <U,V> to the receiver!\n");
    
    printf("##########DECRYPTION##########\n");
    decryption(Sid, pairing, U, xor_result, xor_result_receiver);
    printf("\nThe recovery message digest is %s\n", xor_result_receiver);
    printf("The original message digest is %s\n", shamessage);
    
  if (strcmp(xor_result_receiver, shamessage) == 0) {
        
    printf("Yeah!The message has been decrpted!\n");
  }
    
  else {
    printf("Oops!The message can not be decrpted!\n");
  }
    
  //Free space
  element_clear(P);
  element_clear(Ppub);
  element_clear(Qid);
  element_clear(Sid);
  element_clear(U);
  element_clear(s);
  pairing_clear(pairing);
    
  return 0;
}