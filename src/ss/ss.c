
#include <string.h>
#include <crypto.h>
#include<openssl/smx.h>
#include "ss_lcl.h"

int SS_poly_rand_smx(SS_POLY *poly, unsigned int length)
{

    const BIGNUM *n = IBE_get0_order();
    SS_poly_rand(poly, length, n);

    // the n cannot be free by BN_free 
    // SIGSEGV when executing  a->flags |= BN_FLG_FREE in BN_free 
    // weird thing
    // possibly, the IBE_get0_order return a constant value
    // BN_free((BIGNUM *)n);

}

int SS_poly_apply_smx(BIGNUM *value, SS_POLY *poly, BIGNUM *x)
{

    const BIGNUM *n = IBE_get0_order();
    return SS_poly_apply(value, poly, x, n);
    // BN_free(n);

}

int BN_mod_add_smx(BIGNUM *res, BIGNUM* a, BIGNUM* b)
{
    const BIGNUM *n = IBE_get0_order();
    BN_CTX *ctx = BN_CTX_new();
    BN_mod_add(res, a, b, n, ctx);

    BN_CTX_free(ctx);
    // BN_free(n);
}


int SS_id2num_init(BIGNUM *res, ID *id, char *filename)
{
    EC_POINT *point = NULL;
    ibe_ec_id2point(&point, id->id, id->length, filename);

    // get the x and z of the point 
    BIGNUM *X = point->X;
    BIGNUM *Z = point->Z;
    
    // calculate the result as X * Z^2
    const BIGNUM *n = IBE_get0_order();
    BIGNUM *tmp = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    if(!BN_mod_sqr(tmp, Z, n, ctx)
        ||!BN_mod_mul(res, X, tmp, n, ctx))
    {
        ERROR("error in calculating X*Z^2");
    }

}

int SS_lagrange_value_smx(BIGNUM *value, BIGNUM **num_list, unsigned int length, 
                        unsigned int i, BIGNUM* x)
{
    const BIGNUM *n = IBE_get0_order();
    SS_lagrange_value(value, num_list, length, i, x, n);
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
