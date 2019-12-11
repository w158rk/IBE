/** 
 * @file sys.h 
 * @brief functions about system params
 * @author Wang Ruikai 
 * @date August 7th, 2019
 */

#ifndef SYS_H 
#define SYS_H 

#include "utils.h"
#include "ds.h"
#ifdef __cplusplus
extern "C" {
#endif
/**
 * @brief set up the system 
 * @param[in] mpk_filename file to store the mpk 
 * @param[in] msk_filename file to store the msk 
 * @return 1 if no error, 0 else
 */
int sys_setup(const char* mpk_filename, const char* msk_filename);

/**
 * @brief get mpk from file 
 * @param[in] mpk_filename file to store mpk 
 * @param[out] mpk 
 * @return 1 if no error, 0 else
 */
int get_mpk_fp(const char* mpk_filename, IBEPublicParameters* mpk);

/**
 * @brief get msk from file 
 * @param[in] msk_filename file to store msk 
 * @param[out] msk 
 * @return 1 if no error, 0 else
 */

int put_mpk_fp(const char* mpk_filename, IBEPublicParameters* mpk, long mpk_len);

int get_msk_fp(const char* msk_filename, IBEMasterSecret* msk);

/**
 * @brief get sk from file 
 * @param[in] sk_filename file to store sk 
 * @param[out] sk 
 * @return 1 if no error, 0 else
 */
int get_sk_fp(const char* sk_filename, IBEPrivateKey* sk);

/**
 * @brief get sk from file 
 * @param[in] sk_filename file to store sk 
 * @param[in] sk 
 * @return 1 if no error, 0 else
 */
int put_sk_fp(const char* sk_filename, IBEPrivateKey* sk, long);

/**
 * @brief get the hash point from user's ID 
 * @return 1 if no errors, else 0
 * @param[out] point, input the address of NULL point
 * @param[in] mpk domain encryption parameters
 * @param[in] id 
 * @param[in] id_len
 */


int sys_id2point(
    EC_POINT **point,
    IBEPublicParameters *mpk,
    size_t mpk_len,
    const char* id,
    size_t id_len
);

/**
 * @brief get the group generator 
 * @return 1 if no errors, else 0 
 * @param[out] point, input the address of a NULL point
 */
int sys_getGroupGen(EC_POINT **point);

/**
 * @brief get the public master point
 * @return 1 if no errors, else 0 
 * @param[out] point, input the address of a NULL point
 * @param[in] mpk domain encryption parameters
 */
int sys_getPointPpub(
    EC_POINT **point, 
    IBEPublicParameters *mpk,
    size_t mpk_len 
);
#ifdef __cplusplus
}
#endif

#endif