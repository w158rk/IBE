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
#define SEC_HEAD_LEN    24
#define SIGN_LEN        32
#define MES_LEN         10000

typedef struct ID_STR{
    char *id;
    char *ip;
    int length;
    int port;
    struct ID_STR *father_node;
}ID;



/**
 * packet process context
 */

enum state {
    SEND_APP_PACKET,
    SEND_SIGN,
    SEND_ENC,
    SEND_SEC_PACKET,
    SEND_DONE,

    RECV_DONE,
    RECV_APP_PACKET,
    RECV_VERIFY,
    RECV_DEC,
    RECV_SEC_PACKET,
};

void ID_init();

#endif