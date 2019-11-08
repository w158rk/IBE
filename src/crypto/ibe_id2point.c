/**
 * file: ibe_id2point.c
 */

#include <utils.h>
#include <crypto.h>

#include <openssl/sm9.h>
#include <openssl/bn.h>
#include <openssl/ec.h>

/*  the caller should ensure that mpk_file end with '\0' */
/* different from the id-point map in sm9, here the addition with Ppub is cancelled 
	as at the initial phase, there is no Ppub at all   */
int ibe_id2point_init(
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

	/* parse Q_B = H1(ID_B||hid) * P1 */
	// we should check mpk->hash1
	if (!SM9_hash1(hash1_md, &h, id, id_len, SM9_HID_ENC, n, bn_ctx)
		|| !EC_POINT_mul(group, C, h, NULL, NULL, bn_ctx)) {
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

