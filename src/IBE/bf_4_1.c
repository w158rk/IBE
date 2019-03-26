/**
 Boneh-Franklin Identity-Based Encryption from the Weil Pairing
 Author: Ran Zhao
 Created on: Oct 4th, 2012
 This file is the implementation of BasicIdent scheme of the IBE system.(Chapter 4.1)
 This code needs GMP and PBC library.
 
 Flow Chart:
 (1)Setup:Take secruity parameter K(QBITS,RBITS),return the system parameter ans master
 key of the PKG.The system parameters include a description of a finite message space M,
 and a dscription of a finite ciphertext space C. The system parameters will be publicly
 known,while the master-key will be known only to the PKG.
 (2)Extract:The receiver extracts the corresponding private key from the PKG.
 (3)Encrypt:The sender will generate a ciphertext based on the receiver ID.
 (4)Decrypt:The receiver will use his private key to get the message digest.
 
 Detail:
 1.H1 function---Element build-in function(element_from_hash)
 2.H2 function---SHA1 function generate 160 bit long number
 3.As I use SHA1 function as H2 function, thus the n is automatically set as 160.
 4.In my code, I use type A parameter to generate pairing.
 */



#include"bf_4_1.h"

#define SIZE 100



void get_private_key(char* ID, pairing_t pairing, element_t s, element_t Sid)
{
    element_t PublicKey;
    element_init_G1(PublicKey, pairing);
    element_init_G1(Sid, pairing);
    
    element_from_hash(PublicKey, ID, strlen(ID));   //Compute user public key
    element_mul_zn(Sid, PublicKey, s);   //Compute user private key
    // Sid = PrivateKey;
}

void get_public_key(char* ID, pairing_t pairing, element_t Qid)
{
    
  element_t PrivateKey;
  element_init_G1(Qid, pairing);
  element_init_G1(PrivateKey, pairing);
    
  element_from_hash(Qid, ID, strlen(ID));   //Compute user public key
}

void encryption(char* message, char* ID, element_t P, element_t P_pub,
                element_t U, char* V, pairing_t pairing)
{       // 40个字节,320位的加密

  int i, n=400;
  char sgid[SIZE];   //Sender gid string representation
  char shagid[SIZE]; //Sender H2 function result
  char *buff = (char*)malloc(n);
  memset(buff, 0, n);
  strcpy(buff, message);
    
  element_t r;
  element_t Qid;
  element_t gid;
  element_init_GT(gid, pairing);
  element_init_Zr(r, pairing);
  element_random(r);
  element_mul_zn(U, P, r);
  get_public_key(ID, pairing, Qid);
  //printf("%s\n", ID);
  element_pairing(gid, Qid, P_pub);
  element_pow_zn(gid, gid, r);
  element_snprint(sgid, SIZE, gid);
  sha_fun(sgid, shagid);
  //printf("[enc]%s\n",sgid);
    
  //Do the XOR operation to the shamessage and shagid
    xor_operation_char(buff, shagid, V, 40);
    
//   //..("\nV=%s\n", V);
//     //..("%d\n", &U);
}

void decryption(element_t Sid, pairing_t pairing, element_t U, char* V,
                char* xor_result_receiver)
{
    
  int i;
  element_t rgid;
  char sgid_receiver[SIZE]; //Receiver calculated gid string representation
  char shagid_receiver[SIZE]; //Receiver H2 function result
  element_init_GT(rgid, pairing);
  element_pairing(rgid, Sid, U);
  element_snprint(sgid_receiver, SIZE, rgid);
  //printf("[dec]%s\n",sgid_receiver);
  sha_fun(sgid_receiver, shagid_receiver);  //Generate H2(e(dID,U));
    
  //XOR V and the hash result above
    xor_operation_char(V, shagid_receiver, xor_result_receiver, 40);
    
}

void setup_sys(int rbits,int qbits,element_t P,element_t Ppub,pairing_t pairing,element_t s )
{
    
    pbc_param_t par;   //Parameter to generate the pairing
    pbc_param_init_a_gen(par, rbits, qbits); //Initial the parameter for the pairing
    pairing_init_pbc_param(pairing, par);   //Initial the pairing
        
        
    //In our case, the pairing must be symmetric
    if (!pairing_is_symmetric(pairing))
        pbc_die("pairing must be symmetric");
        
    element_init_G1(P, pairing);
    element_init_G1(Ppub, pairing);
    element_init_Zr(s, pairing);
    element_random(P);
    element_random(s);
    element_mul_zn(Ppub, P, s);

    output_sys("pairing.conf",par);
    output_par("point.conf",P);
    output_par("public.conf",Ppub);
    output_par("private.conf",s);
}

void output_str(const char* filename, char *string) {
    FILE* f = fopen(filename, "w");
    fwrite(string, strlen(string), 1, f);
    fclose(f);
}

void output_sys(const char* filename, pbc_param_t par) {
    FILE* f = fopen(filename, "w");
    pbc_param_out_str(f, par);
    fclose(f);
}

void output_par(const char* filename, element_t s) {
    FILE *f;
    if((f=fopen(filename,"w"))==NULL)
    {
        //printf("open file %s error.\n",filename);
        return ;
    }
    char buff[500];
    memset(buff, '\0', 500);
    int length = element_to_bytes(buff, s);
    fwrite(buff, length, 1, f);
    // element_out_str(f, 16, s);
    fclose(f);
}

