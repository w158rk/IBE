#include<ss_lcl.h>

#include<crypto.h>
#include<openssl/sm9.h>

int SS_poly_rand_sm9(SS_POLY *poly, unsigned int length)
{

    BIGNUM *p = SM9_get0_prime();
    SS_poly_rand(poly, length, p);
    BN_free(p);

}

int SS_poly_apply_sm9(BIGNUM *value, SS_POLY *poly, BIGNUM *x)
{

    BIGNUM *p = SM9_get0_prime();
    SS_poly_apply(value, poly, x, p);
    BN_free(p);

}

int BN_mod_add_sm9(BIGNUM *res, BIGNUM* a, BIGNUM* b)
{
    BIGNUM *p = SM9_get0_prime();
    BN_CTX *ctx = BN_CTX_new();
    BN_mod_add(res, a, b, p, ctx);

    BN_CTX_free(ctx);
    BN_free(p);
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