

#ifndef SS_H
#define SS_H 

#ifdef __cplusplus
extern "C" {
#endif

#include <openssl/bn.h>
#include <openssl/ec.h>

#include "utils.h"
#include "ds.h"


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
#define SS_MAX_ID_LENGTH        256
#define SS_P_BITS               256
#define SS_BN_HEX_LEN            (SS_P_BITS/4 + 1)
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
/** 
 * @brief allocate space for a polynomial 
 * @return the pointer to the polynomial 
 */
SS_POLY *SS_POLY_new(void) ;


/**
 * @brief map the id to a number, generally, it's the x-value of the mappoint
 * 
 * @return 
 *      0 if something is wrong 
 *      1 else 
 * 
 * @param[out] x        where to store the number, must be initialized with 
 *                      BN_new 
 * @param[in] id        the information
 * @param[in] filename  the file to store the mpk
 */
int SS_id2num_init(BIGNUM *x, ID *id, char *filename);

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
 */
int SS_poly_rand_smx(SS_POLY *poly, unsigned int length);

int SS_poly2str(char *res, SS_POLY *poly);
SS_POLY *SS_str2poly(char *in, unsigned int co_cnt);

/**
 * @brief add two big numbers, res = a+b (mod p(smx))
 *
 * @return
 *      0 if something is wrong 
 *      1 if things go smoothly
 *
 * @param[out] res      result 
 * @param[in]  a    
 * @param[in]  b    
 *                      
 */
int BN_mod_add_smx(BIGNUM *res, BIGNUM* a, BIGNUM* b);


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
 */
int SS_poly_apply_smx(BIGNUM *value, SS_POLY *poly, BIGNUM *x);

/**
 * @brief get the Lagrange value give i and x, means get the 
 *                      y = l_i(x) 
 *
 * @return 
 *      0 if something is wrong 
 *      1 if things go smoothly 
 *
 * @param[out]  value           the result of the calculation 
 * @param[in]   num_list        the list of x_j
 * @param[in]   length          the number of the x_j 
 * @param[in]   i               the index of x_i 
 * @param[in]   x               the value of x 
 */

int SS_lagrange_value_smx(BIGNUM *value, BIGNUM **num_list, unsigned int length, 
                        unsigned int i, BIGNUM* x);

/**
 * @brief add two point
 * 
 * @return 1 if no error, 0 else
 *  
 * @param[out]  point    inupt address of a NULL point 
 * @param[in]   left 
 * @param[in]   right   
 */ 


/****************************************************
 * for python use 
 ***************************************/

char *SS_new_rand_poly_py(UINT length);

/**
 * @brief apply
 * 
 * @return the BN value if success, NULL else
 *  
 * @param[in]   poly_str 
 * @param[in]   len: the number of coefficients   
 * @param[in]   bn_str   
 */ 
char *SS_poly_apply_py(char *poly_str, UINT len, char *bn_str);

char *SS_id2num_py(char *id, UINT len, char *);

char *SS_cal_share_py(int len, char *val_list, char *id_list, int *id_len_list, char *mpk_file);

char *SS_cal_xP_py(char *x_str, char *mpk_file);

/**
 * @brief output Ppub1 and Ppub2 to the mpk_file
 * 
 * @return 1 if success, 0 otherwise
 *  
 * @param[in]   in: the string of Ppub1 + '\0' + Ppub2
 * @param[in]   mpk_file   
 */ 
int SS_output_sP_py(char *in, const char *mpk_file);

#ifdef __cplusplus
}
#endif
#endif 

