/**
 * file: ibe_id2point.c
 */

#include <utils.h>
#include <crypto.h>

#include <openssl/sm9.h>
#include <openssl/bn.h>
#include <openssl/ec.h>

/*  the caller should ensure that mpk_file end with '\0' */
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

    SM9PublicParameters *sm9_mpk = NULL;

    FILE *mpk_fp = fopen(mpk_file, "rb");
    if (!d2i_SM9PublicParameters_fp(mpk_fp, &sm9_mpk)){
		ERROR(" get mpk failed");
        goto end;
    }
    
    fclose(mpk_fp);

	EC_GROUP *group = NULL;
	EC_POINT *Ppube = NULL;
	EC_POINT *C = NULL;
	BN_CTX *bn_ctx = NULL;
	BIGNUM *h = NULL;
	const EVP_MD *hash1_md;
	const BIGNUM *n = SM9_get0_order();

    /** use sha-256 as default hash function */
	/** allocate the spaces */
	if (!(group = EC_GROUP_new_by_curve_name(NID_sm9bn256v1))
		|| !(Ppube = EC_POINT_new(group))
		|| !(C = EC_POINT_new(group))
		|| !(bn_ctx = BN_CTX_new())) {
		
		ERROR(" the allocation failed");
		goto end;
	}



	BN_CTX_start(bn_ctx);

	/* parse Ppube */
	if (!EC_POINT_oct2point(group, Ppube, ASN1_STRING_get0_data(sm9_mpk->pointPpub),
		ASN1_STRING_length(sm9_mpk->pointPpub), bn_ctx)) {
		ERROR("parse Ppub failed");
		goto end;
	}

	switch (OBJ_obj2nid(sm9_mpk->hash1)) {
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

	/* parse Q_B = H1(ID_B||hid) * P1 + Ppube */
	// we should check mpk->hash1
	if (!SM9_hash1(hash1_md, &h, id, id_len, SM9_HID_ENC, n, bn_ctx)
		|| !EC_POINT_mul(group, C, h, NULL, NULL, bn_ctx)
		|| !EC_POINT_add(group, C, C, Ppube, bn_ctx)) {
		ERROR("parse QB failed");
		goto end;
	}

	*point = C;
	ret = 1;

end:
	EC_GROUP_free(group);
	EC_POINT_free(Ppube);
	if (bn_ctx) {
		BN_CTX_end(bn_ctx);
	}
	BN_free(h);
	BN_CTX_free(bn_ctx);
	return ret;
    
}

