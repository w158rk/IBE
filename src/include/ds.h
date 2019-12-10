#ifndef DS_H 
#define DS_H

#ifdef __cplusplus
extern "C" {
#endif


#include<stdio.h>
#include<openssl/ec.h>
#include<openssl/bn.h>

/* wrap some library functions */

#define BN_bn2str(x) BN_bn2hex(x)
#define BN_str2bn(a,b) BN_hex2bn(a,b)
char *ibe_ec2str(EC_POINT *point, BN_CTX* ctx);
EC_POINT *ibe_str2ec(char *str, EC_POINT *point, BN_CTX *ctx);

EC_POINT *ibe_EC_POINT_new(); 
// EC_POINT_new(EC_GROUP_new_by_curve_name(NID_sm9bn256v1))

    // EC_POINT_hex2point(EC_GROUP_new_by_curve_name(NID_sm9bn256v1), str, point, ctx)
// #define SS_ec2bn(a,b) BN_hex2bn(a,b)


/**
 * wrap of sm9
 */


typedef char    *IBEPublicParameters;
typedef char    *IBEPrivateKey;
typedef char    *IBEMasterSecret;
typedef struct point_t point_t;

/** 
 * protocol packets
 * 
 */

#define APP_HEAD_LEN    8
/* 24 originally */
#define SEC_HEAD_LEN    8
#define BUFFER_LEN      1000000       
#define SIGN_LEN        16
#define SIGN_ID_LEN     8
#define MES_LEN         10000
#define ENC_PARAMETER       1
#define DEC_PARAMETER       0
#define GLOBAL_MPK_FILENAME "mpk-global.conf"

typedef struct ID_STR{
    char *id;
    char *ip;
    int length;
    int port;
    struct ID_STR *father_node;
}ID;

struct SignMesg
{
    char id_len[SIGN_ID_LEN];
    char sign_len[SIGN_LEN];
    char *ID;
    IBEPublicParameters PP;
    char *sign_data;
    struct SignMesg *front;
};

int ID_equal(ID *a, ID *b);

#ifdef __cplusplus
}
#endif

#endif