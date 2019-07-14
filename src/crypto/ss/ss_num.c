/**
 * @file ss_num.c 
 * @author Wang Ruikai 
 * @date July 13, 2019 
 * @brief number operations for secret sharing 
 * */

#include "./ss.h"

/**
 * @brief calculate the value of a^b 
 * @param[out]  r       the result 
 * @param[in]   a       the base 
 * @param[in]   b       the exponent 
 * @param[in]   m       the moduli 
 * @return      1 if everything goes smoothly
 */

int BN_mod_pow(BIGNUM *r, const BIGNUM *a, const int b, const BIGNUM *m) {

    int it = b;
    BIGNUM *temp1  = BN_new();
    BIGNUM *temp2  = BN_new();
    BIGNUM *temp  = BN_new();;
    BN_copy(temp, m);
    BN_one(r);          /*set to 1*/

    BN_CTX *mul_ctx = BN_CTX_new();
    BN_CTX *sqr_ctx = BN_CTX_new();

    while (0 != it) {
        /* @todo here we use the unsecure method using conditional 
         *       jumps to implement the algorithm. THis method is
         *       is known as subject to the side-channel attacks.
         *       We can modufy this part after the whole things are 
         *       settled
         */
        
        int flag = b & 1;
        if(flag) {

            if(0 == BN_mod_mul(temp, r, temp1, m, mul_ctx)) 
                goto end;
            r = temp;

        } 
        
        if(0 == BN_mod_sqr(temp2, temp1, m, sqr_ctx)) 
            goto end;

        /* exchange the points, in case the multiple call of new method*/
        temp = temp1;
        temp1 = temp2;
        temp2 = temp;
    }
        
    BN_clear_free(temp);
    BN_clear_free(temp1);
    BN_clear_free(temp2);
    return 1;

end:
    BN_clear_free(temp);
    BN_clear_free(temp1);
    BN_clear_free(temp2);
    BN_clear(r);    
    return 0;

}

int SS_poly_rand(SS_POLY* poly, unsigned int length, BIGNUM *p) {
        
    int i=0;
    /* allocate the space for the coefficients */
    BIGNUM **coeff_list = (BIGNUM **)malloc(length * sizeof(BIGNUM *));

    BIGNUM *zero = BN_new();
    BN_zaro(zero);              /*set to zero*/

    BIGNUM *raw = BN_new();
    BIGNUM *final = BN_new();

    /* generate the random coefficients */
    for (i=0; i<length; ++i) {
        if(0 == BN_rand(raw, SS_P_BITS, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY))
            goto end;
        
        /* get the value to the range [0, p-1] */
        if(0 == BN_mod_add_quick(final, raw, zero, p)) goto end;

        coeff_list[i] = final;
    }

    poly -> length = length;
    poly -> coeff = coeff_list;
    return 1;

end:
    return 0;

}

int SS_poly_apply(BIGNUM *value, SS_POLY *poly, BIGNUM *x, BIGNUM *p) {

        

}
