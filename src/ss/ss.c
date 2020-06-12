
#include <string.h>
#include <crypto.h>
#include<openssl/smx.h>
#include "ss_lcl.h"

char *SS_new_rand_poly_py(UINT length)
{
    printf("mark\n");
    SS_POLY *poly = SS_POLY_new();
    SS_poly_rand_smx(poly, length);
    char *buf = malloc(length * SS_BN_HEX_LEN);
    if(SS_poly2str(buf, poly))
    {
        return buf;
    } 
    return NULL;
}


char *SS_poly_apply_py(char *poly_str, UINT len, char *bn_str)
{
    char *ret = NULL;
    SS_POLY *poly = SS_str2poly(poly_str, len);
    BIGNUM *res = BN_new();
    BIGNUM *bn = NULL;

    if(!BN_str2bn(&bn, bn_str))
    {
        goto end_2;
    }
    
    if(!SS_poly_apply_smx(res, poly, bn))
    {
        goto end_1;
    }

    ret = BN_bn2str(res);

end_1:
    BN_free(bn);
end_2:
    BN_free(res);
    free(poly);
    return ret;
}

int SS_poly_rand_smx(SS_POLY *poly, unsigned int length)
{
    poly->length = length;
    
    const BIGNUM *n = IBE_get0_order();
    return SS_poly_rand(poly, length, n);

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

/**
 *  @brief calculate the share with formula
 *              share = \sum f_j(x_i) l_i(0)
 * 
 *  @param[in]  len             the number of users N
 *  @param[in]  val_list        values f_j(x_0) for j in [0, N-1]
 *                              with fixed length 65
 *  @param[in]  id_list         strings for the IDs
 *  @param[in]  id_len_list     lengths of ID strings
 * 
 * @return the value
 */
char *SS_cal_share_py(int len, char *val_list, char *id_list, int *id_len_list, char *mpk_file)
{
    char *ret = NULL;
    
    // allocate space
    BIGNUM **bn_val_list = (BIGNUM **)malloc(len * sizeof(BIGNUM *));
    BIGNUM **bn_id_list = (BIGNUM **)malloc(len * sizeof(BIGNUM *));
    BIGNUM *bn = NULL;
    BIGNUM *zero = NULL;
    BIGNUM *l = NULL;   // for lagrange value
    const BIGNUM *n = IBE_get0_order();
    BN_CTX *ctx = BN_CTX_new();
    ID id;          // temp use
    int i;
    char *p;
    int *plen;

    l = BN_new();
    zero = BN_new();
    BN_zero(zero);

    for (i=0; i<len; i++)
    {
        bn_val_list[i] = NULL;
    }
    for (i=0, p=val_list; i<len; i++, p+=SS_BN_HEX_LEN)
    {
        if(!BN_hex2bn(&bn_val_list[i], p))
        {
            goto end_free_val;
        }
    }

    for (i=0; i<len; i++)
    {
        bn_id_list[i] = NULL;
    }
    for (i=0, plen=id_len_list, p=id_list; i<len; i++)
    {
        bn = BN_new();
        id.id = p;
        id.length = *plen;

        if(!SS_id2num_init(bn, &id, mpk_file))
        {
            BN_free(bn);
            goto end_free_all;
        }

        bn_id_list[i] = bn;
        p += id.length+1;
        plen ++;
    }

    // summarize the bn_val_list
    bn = BN_new();
    BN_zero(bn);
    for (i=0; i<len; i++)
    {
        BN_mod_add_smx(bn, bn, bn_val_list[i]);
    }   

    // calculate the lagrange value
    if(!SS_lagrange_value_smx(l, bn_id_list, len, 0, zero))
    {
        goto end_free_all;
    }

    // multiply l with bn 
    BN_mod_mul(bn, bn, l, n, ctx);
    ret = BN_bn2str(bn);

end_free_all:
    for (i=0; i<len; i++)
    {
        if(bn_id_list[i]) {
            BN_free(bn_id_list[i]);
        }
        else {
            break;
        }        
    }
end_free_val:
    for (i=0; i<len; i++)
    {
        if(bn_val_list[i]) {
            BN_free(bn_val_list[i]);
        }
        else {
            break;
        }
    }

    BN_free(bn);
    BN_free(l);
    BN_free(zero);
    BN_CTX_free(ctx);

    return ret;
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
    ibe_ec_id2point_common(&point, id->id, id->length, filename);

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

char *SS_id2num_py(char *id_str, UINT len, char *mpk_file)
{
    char *ret = NULL;
    ID id;
    id.id = id_str;
    id.length = len;

    BIGNUM *bn = BN_new();
    if(!SS_id2num_init(bn, &id, mpk_file))
    {
        goto end;
    }

    ret = BN_bn2str(bn);

end:
    BN_free(bn);
    return ret;
}


int SS_lagrange_value_smx(BIGNUM *value, BIGNUM **num_list, unsigned int length, 
                        unsigned int i, BIGNUM* x)
{
    const BIGNUM *n = IBE_get0_order();
    SS_lagrange_value(value, num_list, length, i, x, n);
}

/**
 *  @brief the res will be changed no matter the return value is 1 or not
 * 
 * the size of res should be at least 65 * N, where N is the number of the coeffs
 */
int SS_poly2str(char *res, SS_POLY *poly)
{
    int ret = 0;

    BIGNUM *cur_bn = NULL;
    char *cur_str = NULL;
    char *cur_ptr = res;
    int bn_len = 64;
    int cur_len = 0;
    int i = 0;

    for (i=0; i<poly->length; i++)
    {

        cur_bn = poly->coeff[i];
        cur_str = BN_bn2str(cur_bn);
        cur_len = strlen(cur_str);

        if(cur_len > bn_len)
        {
            goto end;
        }

        memcpy(cur_ptr, cur_str, cur_len);
        cur_ptr += bn_len;
        *cur_ptr = '\0';
        cur_ptr ++;
    }

    ret = 1;

end:
    if(cur_str)
    {
        free(cur_str);
    }
    return ret;


}

/**
 *  @brief generate a SS_POLY struct from a string
 * 
 *  @param[in] in       the input string 
 *  @param[in] co_cnt   the number of coefficients 
 * 
 * @return the polynomial
 * the returned result should be freed by the caller
 */
SS_POLY *SS_str2poly(char *in, unsigned int co_cnt)
{
    SS_POLY *ret = SS_POLY_new();
    BIGNUM *bn = NULL;
    char buf[65];
    char *p = in;
    int bn_len = 65;

    int i;
    ret->coeff = (BIGNUM **)malloc(co_cnt * sizeof(BIGNUM *));
    for(i=0; i<co_cnt; i++)
    {
        memcpy(buf, p, bn_len);
        if(BN_hex2bn(&bn, buf))
        {
            ret->coeff[i] = bn;
            bn = NULL;
        }
        p += bn_len;
    }

    ret->length = co_cnt;
    return ret;

fail:
    free(ret);
    return NULL;

}
