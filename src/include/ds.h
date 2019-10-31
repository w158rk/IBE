#ifndef DS_H 
#define DS_H

#include<stdio.h>
#include<openssl/ec.h>
#include<openssl/bn.h>

/**
 * wrap of sm9
 */

#define IBE_SK_LEN      313     /* > 313 */
#define IBE_PP_LEN      104  /* public parameters > 104*/
#define IBE_MS_LEN      139  /* master secret  > 139*/

typedef char    *IBEPublicParameters;
typedef char    *IBEPrivateKey;
typedef char    *IBEMasterSecret;


/** 
 * protocol packets
 * 
 */

#define APP_HEAD_LEN    8
/* 24 originally */
#define SEC_HEAD_LEN    8       
#define SIGN_LEN        32
#define MES_LEN         10000
#define ENC_PARAMETER       1
#define DEC_PARAMETER       0

typedef struct ID_STR{
    char *id;
    char *ip;
    int length;
    int port;
    struct ID_STR *father_node;
}ID;





void ID_init();

#endif