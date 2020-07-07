#ifndef IBE_H 
#define IBE_H 

// #include "utils.h"
#include "ds.h"


/**
 * @brief map an ID to point 
 * @return 1 if no errors , else 0
 * @param[out] point the initial value of point should be the address of a NULL point
 * @param[in] id ID
 * @param[in] id_len length of ID
 * @param[in] mpk_file the filename of the file where the mpk is stored, should end with '\0
 */
int ibe_ec_id2point(
    EC_POINT **point,    
    char *id, 
    long id_len,
    char *mpk_file
); 
int ibe_ec_id2point_common(EC_POINT **point, char *id, long id_len, char *mpk_file);

int ibe_setup(
    char *mpk_file,
    char *msk_file,
    char *mpk_len_file,
    char *msk_len_file
);

int ibe_encrypt(const char* data, size_t data_len,  char* c_buf, size_t *c_len, 
    IBEPublicParameters *mpk, long mpk_len, const char *id, size_t id_len);
int ibe_decrypt(const char* c_buf, size_t c_len,  char* m_buff, size_t *m_len, 
    IBEPrivateKey *sk, long sk_len);
int ibe_sign(const char* data, size_t data_len,  char* sign_buf, size_t *sign_len, 
    IBEPrivateKey *sk, long sk_len);
int ibe_verify(const  char* data, size_t data_len,  char* sign_buf, size_t sign_len, 
    IBEPublicParameters *mpk, long mpk_len, const char *id, size_t id_len);

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

// EC
EC_GROUP *ibe_get_ec_group();

/**
 * @brief calculate res = xP where x in a number and P is the generator of the group 
 */
int ibe_ec_cal_xP1(EC_GROUP **group, EC_POINT **res, BIGNUM *x, char *mpk_file);



/**
 * @brief calculate res = xQ where x in a number and Q is an arbitrary point in the group 
 */
int ibe_ec_cal_xQ(EC_GROUP **group_ptr, EC_POINT **point, BIGNUM *x, EC_POINT *Q, char *mpk_file);


// int ibe_sign(const unsigned char *data, size_t data_length, const unsigned char* sign, size_t *sign_length, SM9PrivateKey *sk);
// int ibe_verify(const unsigned char* data, size_t data_length, const unsigned char *sign, size_t sign_length, SM9PublicParameters *mpk, const char *id, size_t id_length);

/* replace the sP in the mpk file with point */
int ibe_ec_store_Ppub1(EC_POINT *point, char *mpk_file);
int ibe_point_store_Ppub2(point_t *point, char *mpk_file);
int ibe_ec_store_sk(EC_POINT *sQ, char *id, UINT id_len, char *mpk_file, char *sk_file);

// wrap for point_t
/**
 * @brief calculate res = xP2 where x in a number and P2 is the generator of the group G2
 */
int ibe_point_cal_xP2(point_t *res, BIGNUM *x, char *mpk_file);
int ibe_point_from_octets(point_t **point, char *buf);
int ibe_point_to_octets(point_t *point, char *buf);
int ibe_point_copy(point_t *to, point_t *from);
point_t *ibe_point_new(void);
void ibe_point_free(point_t *);
int ibe_point_add(point_t *res, point_t *a, point_t *b);
int ibe_point_is_on_curve(point_t *point);


char *ibe_point_cal_xP2_py(char *x_str, char *mpk_file);
char *ibe_ec_cal_xP1_py(char *x_str, char *mpk_file);

// utils 
int ibe_gen_sk_filename(char **to, ID *id);
int ibe_gen_sk_len_filename(char **to, ID *id);
int ibe_gen_mpk_filename(char **to, ID *id);
void ibe_free_filename(char *filename);


const BIGNUM *IBE_get0_generator2_x0(void);
const BIGNUM *IBE_get0_generator2_x1(void);
const BIGNUM *IBE_get0_generator2_y0(void);
const BIGNUM *IBE_get0_generator2_y1(void);
const BIGNUM *IBE_get0_prime(void);
const BIGNUM *IBE_get0_order(void);
const BIGNUM *IBE_get0_order_minus_one(void);
const BIGNUM *IBE_get0_loop_count(void);
const BIGNUM *IBE_get0_final_exponent(void);
const BIGNUM *IBE_get0_fast_final_exponent_p20(void);
const BIGNUM *IBE_get0_fast_final_exponent_p21(void);
const BIGNUM *IBE_get0_fast_final_exponent_p22(void);
const BIGNUM *IBE_get0_fast_final_exponent_p23(void);
const BIGNUM *IBE_get0_fast_final_exponent_p3(void);


#endif