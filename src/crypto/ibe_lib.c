# include <openssl/sm9.h>

#include <crypto.h>
#include <string.h>

void ibe_sk_copy(IBEPrivateKey *dest, IBEPrivateKey *src, long sk_len) {
    IBEPrivateKey tmp = (IBEPrivateKey)malloc(sk_len);
    memcpy(tmp, *src, sk_len);
    *dest = tmp;
}

int ibe_get_group_id()
{
    return NID_sm9bn256v1; 
}

int ibe_cal_xP(EC_GROUP **group_ptr, EC_POINT **point, BIGNUM *x, char *mpk_file)
{

    int ret = 0;
	if(*point != NULL || *group_ptr != NULL)
	{
		ERROR("[ibe_cal_xp] the input point or group is not NULL");
		goto end;
	}

    // read the mpk from file 

    SM9PublicParameters *sm9_mpk = NULL;

    FILE *mpk_fp = fopen(mpk_file, "rb");
    if (!d2i_SM9PublicParameters_fp(mpk_fp, &sm9_mpk)){
		ERROR(" get mpk failed");
        goto end;
    }
    
    fclose(mpk_fp);

	EC_GROUP *group = NULL;
	EC_POINT *C = NULL;
	BN_CTX *bn_ctx = NULL;
	const BIGNUM *n = SM9_get0_order();

	/** allocate the spaces */
	if (!(group = EC_GROUP_new_by_curve_name(NID_sm9bn256v1))
		|| !(C = EC_POINT_new(group))
		|| !(bn_ctx = BN_CTX_new())) {
		
		ERROR(" the allocation failed");
		goto end;
	}

	BN_CTX_start(bn_ctx);

    // calculate C = xP
	if (!EC_POINT_mul(group, C, x, NULL, NULL, bn_ctx)) {
		ERROR("parse xP failed");
		goto end;
	}

	*group_ptr = group;
	*point = C;
	ret = 1;

end:
	if (bn_ctx) {
		BN_CTX_end(bn_ctx);
	}
	BN_CTX_free(bn_ctx);
	return ret;

}

int ibe_cal_xQ(EC_GROUP **group_ptr, EC_POINT **point, BIGNUM *x, EC_POINT *Q, char *mpk_file)
{

    int ret = 0;
	if(*point != NULL || *group_ptr != NULL)
	{
		ERROR("[ibe_cal_xp] the input point or group is not NULL");
		goto end;
	}

    // read the mpk from file 

    SM9PublicParameters *sm9_mpk = NULL;

    FILE *mpk_fp = fopen(mpk_file, "rb");
    if (!d2i_SM9PublicParameters_fp(mpk_fp, &sm9_mpk)){
		ERROR(" get mpk failed");
        goto end;
    }
    
    fclose(mpk_fp);

	EC_GROUP *group = NULL;
	EC_POINT *C = NULL;
	BN_CTX *bn_ctx = NULL;
	const BIGNUM *n = SM9_get0_order();

	/** allocate the spaces */
	if (!(group = EC_GROUP_new_by_curve_name(NID_sm9bn256v1))
		|| !(C = EC_POINT_new(group))
		|| !(bn_ctx = BN_CTX_new())) {
		
		ERROR(" the allocation failed");
		goto end;
	}

	BN_CTX_start(bn_ctx);

    // calculate C = xQ
	if (!EC_POINT_mul(group, C, NULL, Q, x, bn_ctx)) {
		ERROR("parse xP failed");
		goto end;
	}

	*group_ptr = group;
	*point = C;
	ret = 1;

end:
	if (bn_ctx) {
		BN_CTX_end(bn_ctx);
	}
	BN_CTX_free(bn_ctx);
	return ret;

}
