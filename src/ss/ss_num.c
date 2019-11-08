/**
 * @file ss_num.c 
 * @author Wang Ruikai 
 * @date July 13, 2019 
 * @brief number operations for secret sharing 
 * */

#include "./ss_lcl.h"
#define SWAP(x, y) { temp = x; x = y; y = temp; }

SS_POLY *SS_POLY_new(void) {
    
    SS_POLY *p = (SS_POLY *)malloc(sizeof(SS_POLY));
    return p;

}

int SS_poly_rand(SS_POLY* poly, unsigned int length, BIGNUM *p) {
    /**
     * @todo the check of the validation of the coefficient 
     */
    int i=0;
    /* allocate the space for the coefficients */
    BIGNUM **coeff_list = (BIGNUM **)malloc(length * sizeof(BIGNUM *));
    
    BIGNUM *zero = BN_new();
    BN_zero(zero);              /*set to zero*/

    BIGNUM *raw = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    /* generate the random coefficients */
    for (i=0; i<length; ++i) {
        BIGNUM *final = BN_new();
        if(0 == BN_rand(raw, SS_P_BITS, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY))
            goto end;
        
        /* get the value to the range [0, p-1] */
        if(0 == BN_mod_add(final, raw, zero, p, ctx)) goto end;

        coeff_list[i] = final;
    }

    poly -> length = length;
    poly -> coeff = coeff_list;
    
    BN_CTX_free(ctx);
    return 1;

end:
    BN_CTX_free(ctx);
    return 0;

}

int SS_poly_apply(BIGNUM *value, SS_POLY *poly, BIGNUM *x, BIGNUM *p) {

    int ret = 0;
    int i=0;
    BIGNUM *r = BN_new();
    BN_zero(r);                 /* set as 0*/
    BIGNUM *temp = BN_new();            /* temp variable */
    BIGNUM **coeff_list = poly->coeff;   

    BN_CTX *mul_ctx = BN_CTX_new();
    BN_CTX *add_ctx = BN_CTX_new();

    for (i=poly->length-1; i>0; --i) {
        if(0 == BN_mod_add(temp, r, coeff_list[i], p, add_ctx))
            goto end;
        if(0 == BN_mod_mul(r, temp, x, p, mul_ctx))
            goto end;
    }    

    if(0 == BN_mod_add(value, r, coeff_list[0], p, add_ctx))
        goto end;

    
    ret = 1;

end:    /* something went wrong */
    BN_free(r);
    BN_free(temp);
    BN_CTX_free(mul_ctx);
    BN_CTX_free(add_ctx);
    BN_zero(value);

    return ret;

}

int SS_lagrange_value(BIGNUM *value, BIGNUM **x_list, unsigned int length,
                        unsigned int i, BIGNUM *x, BIGNUM *p)
{
    int ret = 0;

    BIGNUM *numerator = BN_new();
    BIGNUM *denominator = BN_new();
    BIGNUM *r = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *temp = NULL;

    BN_one(numerator);
    BN_one(denominator);

    BN_CTX * ctx = BN_CTX_new();

    /* calculate (x-x1)(x-x2)...(x-xn) */
    /* calculate (xi-x1)(xi-x2)...(xi-xn) */
    
    int j=0;
    for (j=0; j<length; ++j) {
        if(j == i) continue;

        if(0 == BN_mod_sub(d, x, x_list[j], p, ctx)) 
            goto end;
        if(0 == BN_mod_mul(r, numerator, d, p, ctx)) 
            goto end;
        SWAP(r, numerator);

        if(0 == BN_mod_sub(d, x_list[i], x_list[j], p, ctx)) 
            goto end;
        if(0 == BN_mod_mul(r, denominator, d, p, ctx)) 
            goto end;
        SWAP(r, denominator);

    }
    
    /* get the inversion of denominator and multiply it with the numerator */
    BN_mod_inverse(d, denominator, p, ctx);
    if(0 == BN_mod_mul(value, d, numerator, p, ctx))
        goto end;

    ret = 1;
end:

    BN_free(numerator);
    BN_free(denominator);
    BN_free(d);
    BN_free(r);
    BN_CTX_free(ctx);
    return ret;

}
