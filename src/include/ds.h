#ifndef DS_H 
#define DS_H

#ifdef __cplusplus
extern "C" {
#endif


#include<stdio.h>
#include<openssl/ec.h>
#include<openssl/bn.h>

/* wrap some library functions */

#define EC_POINT_new_sm9() EC_POINT_new(EC_GROUP_new_by_curve_name(NID_sm9bn256v1))
#define BN_bn2str(x) BN_bn2hex(x)
#define BN_str2bn(a,b) BN_hex2bn(a,b)
#define EC_ec2str(point, ctx) \
    EC_POINT_point2hex(EC_GROUP_new_by_curve_name(NID_sm9bn256v1), point, POINT_CONVERSION_COMPRESSED, ctx)
#define EC_str2ec(str, point, ctx) \
    EC_POINT_hex2point(EC_GROUP_new_by_curve_name(NID_sm9bn256v1), str, point, ctx)
// #define SS_ec2bn(a,b) BN_hex2bn(a,b)


/**
 * wrap of sm9
 */


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

int ID_equal(ID *a, ID *b);

#ifdef __cplusplus
}
#endif

#endif