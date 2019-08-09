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

typedef struct {
    char head[APP_HEAD_LEN];
    char *payload;
} AppPacket;

typedef struct {
    char head[SEC_HEAD_LEN];
    union payload1 {
        char *data;
        AppPacket *appPacket;
    } payload;
    char signature[SIGN_LEN];
} SecPacket;

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

typedef struct {
    enum state phase;
    union payload2 {
        AppPacket *appPacket;
        SecPacket *secPacket;
        char *data;
    } payload;
    
    char *src_id;
    size_t src_id_len;
    char *dest_id;
    size_t dest_id_len;
    
    IBEPublicParameters *mpk;
    IBEPrivateKey *sk;  

    unsigned char *aes_key;
} PacketCTX;

#endif