/** 
 * @file crypto.h 
 * @author Wang Ruikai 
 * @date July 13th, 2019 
 * @brief File contains the definitions and declarations of the cryptography 
 *              stuffs 
 *      */


#ifndef CRYPTO_H
#define CRYPTO_H 


#include "utils.h"
#include "ds.h"

#include <openssl/bn.h>
#include <openssl/ec.h>


int ibe_encrypt(const unsigned char* data, size_t data_len, unsigned char* c_buf, size_t *c_len, 
    IBEPublicParameters *mpk, const char *id, size_t id_len);
int ibe_decrypt(const unsigned char* c_buf, size_t c_len, unsigned char* m_buff, size_t *m_len, 
    IBEPrivateKey *sk);

/**
 * @brief extract ibe private key 
 * @return 1 if no errors , else 0
 * @param[out] sk private key 
 * @param[in] msk Master Secret
 * @param[in] id the ID of the request launcher
 * @param[in] id_len length of id
 */
int ibe_extract(IBEPrivateKey *sk, 
                IBEMasterSecret* msk, 
                const char* id,
                size_t id_len);


void ibe_sk_copy(IBEPrivateKey *dest, IBEPrivateKey *src);

/*
 * cbc 
 */

/* key lengths */
#define AES_KEY_BITS            256 
#define AES_KEY_LEN             (AES_KEY_BITS/8)
#define AES_IV_BITS             128
#define AES_IV_LEN              (AES_IV_BITS/8)

int put_iv_fp(const char* filename, const char* iv, size_t len);
int get_iv_fp(const char* filename, char* iv, size_t len);
int cbc_decrypt(unsigned char *c, size_t c_len, unsigned char *key,
    unsigned char *iv, unsigned char *m, size_t* m_len);
int cbc_encrypt(unsigned char *m, size_t m_len, unsigned char *key,
    unsigned char *iv, unsigned char *c, size_t* c_len);
int gen_random_iv(char *iv);
int gen_random_key(char *key);

char *cbc_iv_new(void);
char *cbc_key_new(void);

/*
 * secret sharing 
 *
 * This part is the implementation of the secret sharing algorithms
 * including 
 *      generate a random polynomial
 *      apply a value into the random polynomial 
 *              (the value is a big number) 
 *      calculate a Lagrange result given a value x, i --- l_i (x)
 *      point addition --- wrap the library functions  
 *      scalar multiplication --- wrap the library functions 
 *
 */              

/* parameters */ 
#define SS_MAX_ID_LENGTH        SM9_MAX_ID_LENGTH
#define SS_P_BITS               256
#define SS_P_LENGTH             (SS_P_BITS/8)
/* TODO this should be defined in the configure file */
// #define SS_POLY_LENGTH           5      

/* types */
typedef struct {
    BIGNUM          **coeff;
    unsigned int      length;
} SS_POLY;

/* functions */
/* used to unwrap the macro SS_P_BITS*/
/* TODO why ? */
#define CONCAT1(a,b)    a##b
#define CONCAT(a,b)     CONCAT1(a,b)

#define SS_get_p    CONCAT(BN_get0_nist_prime_,SS_P_BITS) 
/** 
 * @brief allocate space for a polynomial 
 * @return the pointer to the polynomial 
 */
SS_POLY *SS_POLY_new(void) ;

/**
 * @brief generate a random polynomial
 *
 * @return
 *      0 if something is wrong 
 *      1 if things go smoothly
 *
 * @param[out] poly     where to store the polynomial 
 * @param[in]  length   the number of coefficients (usually 
 *                      equals to the number of the top nodes)
 * @param[in]  p        the prime field idetification 
 */
int SS_poly_rand(SS_POLY *poly, unsigned int length, BIGNUM *p);

/**
 * @brief get the value of the polynomial given an argument x for that
 *
 * @return 
 *      0 if something is wrong 
 *      1 if things go smoothly 
 *
 * @param[out]  value   the result of the application 
 * @param[in]   poly    the polynomial 
 * @param[in]   x       the argument 
 * @param[in]   p       the prime field identification
 */
int SS_poly_apply(BIGNUM *value, SS_POLY *poly, BIGNUM *x, BIGNUM *p);

/**
 * @brief get the Lagrange value give i and x, means get the 
 *                      y = l_i(x) 
 *
 * @return 
 *      0 if something is wrong 
 *      1 if things go smoothly 
 *
 * @param[out]  value           the result of the calculation 
 * @param[in]   poly_list       the list of x_j
 * @param[in]   length          the number of the x_j 
 * @param[in]   i               the index of x_i 
 * @param[in]   x               the value of x 
 * @param[in]   p               the field identifier
 */

int SS_lagrange_value(BIGNUM *value, BIGNUM **poly_list, unsigned int length, 
                        unsigned int i, BIGNUM* x, BIGNUM *p);

/**
 * @brief add two point
 * 
 * @return 1 if no error, 0 else
 *  
 * @param[out]  point    inupt address of a NULL point 
 * @param[in]   left 
 * @param[in]   right   
 */ 

/*!
 * @todo scalar multiplication of a point and a scalar
 */

#endif 
