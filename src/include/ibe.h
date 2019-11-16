#ifndef IBE_H 
#define IBE_H 

#include "utils.h"
#include "ds.h"

// this should be removed some time
#include <openssl/sm9.h>

/**
 * @brief map an ID to point 
 * @return 1 if no errors , else 0
 * @param[out] point the initial value of point should be the address of a NULL point
 * @param[in] id ID
 * @param[in] id_len length of ID
 * @param[in] mpk_file the filename of the file where the mpk is stored, should end with '\0
 */
int ibe_id2point_init(
    EC_POINT **point,    
    char *id, 
    long id_len,
    char *mpk_file
); 


int ibe_setup(
    char *mpk_file,
    char *msk_file,
    char *mpk_len_file,
    char *msk_len_file
);
int ibe_encrypt(const  char* data, size_t data_len,  char* c_buf, size_t *c_len, 
    IBEPublicParameters *mpk, long mpk_len, const char *id, size_t id_len);
int ibe_decrypt(const  char* c_buf, size_t c_len,  char* m_buff, size_t *m_len, 
    IBEPrivateKey *sk, long sk_len);

/**
 * @brief extract ibe private key 
 * @return 1 if no errors , else 0
 * @param[out] sk private key 
 * @param[in] msk Master Secret
 * @param[in] id the ID of the request launcher
 * @param[in] id_len length of id
 */
int ibe_extract(IBEPrivateKey *sk, 
                long *,
                IBEMasterSecret* msk, 
                long msk_len,
                const char* id,
                size_t id_len);


void ibe_sk_copy(IBEPrivateKey *dest, IBEPrivateKey *src, long);

/**
 * @brief calculate res = xP where x in a number and P is the generator of the group 
 */
int ibe_cal_xP(EC_GROUP **group, EC_POINT **res, BIGNUM *x, char *mpk_file);

/**
 * @brief calculate res = xQ where x in a number and Q is an arbitrary point in the group 
 */
int ibe_cal_xQ(EC_GROUP **group_ptr, EC_POINT **point, BIGNUM *x, EC_POINT *Q, char *mpk_file);


int ibe_sign(const unsigned char *data, size_t data_length, const unsigned char* sign, size_t *sign_length, SM9PrivateKey *sk);
int ibe_verify(const unsigned char* data, size_t data_length, const unsigned char *sign, size_t sign_length, SM9PublicParameters *mpk, const char *id, size_t id_length);

/* replace the sP in the mpk file with point */
int ibe_store_sP(EC_POINT *point, char *mpk_file);
int ibe_store_sQ(EC_POINT *sQ, ID *id, char *mpk_file);

#endif