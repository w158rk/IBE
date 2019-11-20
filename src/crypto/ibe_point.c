/**
 * file: ibe_id2point.c
 */

#include <utils.h>
#include <crypto.h>

#include "smx_lcl.h"


/*  the caller should ensure that mpk_file end with '\0' */
/* parse Q_B = H1(ID_B||hid) * P1 + Ppub1 */
int ibe_id2point(
    EC_POINT **point,    
    char *id, 
    long id_len,
    char *mpk_file
) 
{
	int ret = 0;
	if(*point != NULL)
	{
		ERROR("the input point is not NULL");
		goto end;
	}

    // read the mpk from file 

    SMXPublicParameters *smx_mpk = NULL;

    FILE *mpk_fp = fopen(mpk_file, "rb");
    if (!d2i_SMXPublicParameters_fp(mpk_fp, &smx_mpk)){
		ERROR(" get mpk failed");
        goto end;
    }
    
    fclose(mpk_fp);

	EC_GROUP *group = NULL;
	EC_POINT *C = NULL;
	BN_CTX *bn_ctx = NULL;
	BIGNUM *h = NULL;
	const EVP_MD *hash1_md;
	const BIGNUM *n = SMX_get0_order();

    /** use sha-256 as default hash function */
	/** allocate the spaces */
	if (!(group = EC_GROUP_new_by_curve_name(NID_sm9bn256v1))
		|| !(C = EC_POINT_new(group))
		|| !(bn_ctx = BN_CTX_new())) {
		
		ERROR(" the allocation failed");
		goto end;
	}



	BN_CTX_start(bn_ctx);

	switch (OBJ_obj2nid(smx_mpk->hash1)) {
	case NID_sm9hash1_with_sm3:
		hash1_md = EVP_sm3();
		break;
	case NID_sm9hash1_with_sha256:
		hash1_md = EVP_sha256();
		break;
	default:
		ERROR("Cannot get appropriate hash function iod");
		goto end;
	}

	EC_POINT* Ppube = EC_POINT_new(group);

	/* parse Ppube1 */
	if (!EC_POINT_oct2point(group, Ppube, ASN1_STRING_get0_data(smx_mpk->pointPpub1),
		ASN1_STRING_length(smx_mpk->pointPpub1), bn_ctx)) {
		goto end;
	}

	/* parse Q_B = H1(ID_B||hid) * P1 */
	// we should check mpk->hash1
	if (!SMX_hash1(hash1_md, &h, id, id_len, SMX_HID_ENC, n, bn_ctx)
		|| !EC_POINT_mul(group, C, h, NULL, NULL, bn_ctx)
		|| !EC_POINT_add(group, C, C, Ppube, bn_ctx)) 
	{
		ERROR("parse QB failed");
		goto end;
	}

	*point = C;
	ret = 1;

end:
	EC_GROUP_free(group);
	if (bn_ctx) {
		BN_CTX_end(bn_ctx);
	}
	BN_free(h);
	BN_CTX_free(bn_ctx);
	return ret;
    
}

int ibe_point_to_octets(point_t *point, char *buf)
{
	int rtn = 0;

	if(!point || !buf)
	{
		ERROR("point or out buffer is NULL at the beginning");
		return 0;
	}

	BN_CTX *bn_ctx = BN_CTX_new();
	BN_CTX_start(bn_ctx);

#ifdef DEBUG 
{
	const BIGNUM *p = SMX_get0_prime();
	if(!point_is_on_curve_smx(point, p, bn_ctx))
	{
		ERROR("P is not in the group G2");
	}
	else
	{
		ERROR("P is on the curve");
	}
	
}
#endif

	if(!point_to_octets_smx(point, buf, bn_ctx))
	{
		ERROR("cannot convert P in G2 to string");
		goto end;
	}

#ifdef DEBUG 
{
	const BIGNUM *p = SMX_get0_prime();
	point_t dbg_point;

	if(!point_init_smx(&dbg_point, bn_ctx)
		|| !point_from_octets_smx(&dbg_point, buf, p, bn_ctx))
	{
		ERROR("cannot convert P in G2 to string");
	}
	else 
	{
		ERROR("can convert P in G2 to string at this point");
	}
}
#endif

	rtn = 1;

end:
	if(bn_ctx)	BN_CTX_end(bn_ctx);
	BN_CTX_free(bn_ctx);

	return rtn;

}

int ibe_point_from_octets(point_t **point, char *buf)
{
	int rtn = 0;

	if(*point)
	{
		ERROR("point is not NULL at the beginning");
		return 0;
	}

	const BIGNUM *p = SMX_get0_prime();
	point_t *res = (point_t *)malloc(sizeof(point_t));
	BN_CTX *bn_ctx = BN_CTX_new();
	BN_CTX_start(bn_ctx);

	if(!point_init_smx(res, bn_ctx)
		||!point_from_octets_smx(res, buf, p, bn_ctx))
	{
		ERROR("cannot get pub2 from string");
		goto end;
	}

	*point = res;
	rtn = 1;

end:
	if(bn_ctx)	BN_CTX_end(bn_ctx);
	// BN_CTX_free(bn_ctx);

	return rtn;

}

point_t *ibe_point_new()
{
	point_t *res = (point_t *)malloc(sizeof(point_t));
	BN_CTX *ctx = BN_CTX_new();
	BN_CTX_start(ctx);
	point_init_smx(res, ctx);
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);
	return res;
}

void ibe_point_free(point_t *point)
{
	free(point);
}

int ibe_point_add(point_t *res, point_t *a, point_t *b)
{
	if(!res || !a || !b)
	{
		return 0;
	}

	int ret = 0;
	const BIGNUM *p = SMX_get0_prime();
	BN_CTX *ctx = BN_CTX_new();
	BN_CTX_start(ctx);
	if(!point_add_smx(res, a, b, p, ctx))
	{
		ERROR(" can not add the two point");
		fprintf(stderr, "a is on the curve: %d\n", ibe_point_is_on_curve(a));
		fprintf(stderr, "b is on the curve: %d\n", ibe_point_is_on_curve(b));
		goto end;
	}

	ret = 1;
end:

	BN_CTX_end(ctx);
	BN_CTX_free(ctx);
	return ret;
}

int ibe_point_copy(point_t *to, point_t *from)
{
	return point_copy_smx(to, from);
}
