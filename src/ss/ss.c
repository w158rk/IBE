#include "ss_lcl.h"

#include <string.h>
#include<crypto.h>
#include<openssl/sm9.h>

int SS_poly_rand_sm9(SS_POLY *poly, unsigned int length)
{

    BIGNUM *p = SM9_get0_prime();
    SS_poly_rand(poly, length, p);

    // the p cannot be free by BN_free 
    // SIGSEGV when executing  a->flags |= BN_FLG_FREE in BN_free 
    // weird thing
    // possibly, the SM9_get0_prime return a constant value
    // BN_free((BIGNUM *)p);

}

int SS_poly_apply_sm9(BIGNUM *value, SS_POLY *poly, BIGNUM *x)
{

    BIGNUM *p = SM9_get0_prime();
    return SS_poly_apply(value, poly, x, p);
    // BN_free(p);

}

int BN_mod_add_sm9(BIGNUM *res, BIGNUM* a, BIGNUM* b)
{
    BIGNUM *p = SM9_get0_prime();
    BN_CTX *ctx = BN_CTX_new();
    BN_mod_add(res, a, b, p, ctx);

    BN_CTX_free(ctx);
    // BN_free(p);
}


int SS_id2num_init(BIGNUM *res, ID *id, char *filename)
{
    EC_POINT *point = NULL;
    ibe_id2point_init(&point, id->id, id->length, filename);

    // get the x and z of the point 
    BIGNUM *X = point->X;
    BIGNUM *Z = point->Z;
    
    // calculate the result as X * Z^2
    BIGNUM *p = SM9_get0_prime();
    BIGNUM *tmp = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    if(!BN_mod_sqr(tmp, Z, p, ctx)
        ||!BN_mod_mul(res, X, tmp, p, ctx))
    {
        ERROR("error in calculating X*Z^2");
    }

}

int SS_lagrange_value_sm9(BIGNUM *value, BIGNUM **num_list, unsigned int length, 
                        unsigned int i, BIGNUM* x)
{
    BIGNUM *p = SM9_get0_prime();
    SS_lagrange_value(value, num_list, length, i, x, p);
}

/**
 *  @brief the res will be changed no matter the return value is 1 or not
 */
int SS_poly2str(char *res, int *len, SS_POLY *poly)
{
    int ret = 0;

    BIGNUM **coeff = poly->coeff;
    BIGNUM *cur_bn = NULL;
    char *cur_str = NULL;
    char *cur_ptr = res;
    int cur_len = 0;
    int cnt = poly->length;
    int length = 0;
    int i = 0;

    for (i=0; i<cnt; i++)
    {

        cur_bn = coeff[i];
        cur_str = BN_bn2str(cur_bn);
        cur_len = strlen(cur_str);
        length += cur_len + 1;

        if(*len < length)
        {
            goto end;
        }

        memcpy(cur_ptr, cur_str, cur_len);
        cur_ptr += cur_len;
        *cur_ptr = '\n';
        cur_ptr++;

    }

    *len = length;
    ret = 1;

end:
    if(cur_str)
    {
        free(cur_str);
    }
    return ret;


}
