/**
 * @file sys_id2point.c
 * @author Wang Ruikai 
 * @date August 8th, 2019 
 * @brief get the hash C from the id  
 */

#include <sys.h>
#include <openssl/sm9.h>
#include <openssl/err.h>

#include "sm9_lcl.h"

int sys_id2point(
    EC_POINT **point,
    IBEPublicParameters *mpk,
    size_t mpk_len,
    const char* id,
    size_t id_len
)
{

	int ret = 0;
	EC_GROUP *group = NULL;
	EC_POINT *Ppube = NULL;
	EC_POINT *C = NULL;
	BN_CTX *bn_ctx = NULL;
	BIGNUM *h = NULL;
	const EVP_MD *hash1_md;
	const BIGNUM *n = SM9_get0_order();

    /** use sha-256 as default hash function */

	if (!(group = EC_GROUP_new_by_curve_name(NID_sm9bn256v1))
		|| !(Ppube = EC_POINT_new(group))
		|| !(C = EC_POINT_new(group))
		|| !(bn_ctx = BN_CTX_new())) {
		SM9err(SM9_F_SM9_WRAP_KEY, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	BN_CTX_start(bn_ctx);

    SM9PublicParameters *sm9_mpk = NULL;
    d2i_SM9PublicParameters(&sm9_mpk, mpk, mpk_len);

	/* parse Ppube */
	if (!EC_POINT_oct2point(group, Ppube, ASN1_STRING_get0_data(sm9_mpk->pointPpub),
		ASN1_STRING_length(sm9_mpk->pointPpub), bn_ctx)) {
		SM9err(SM9_F_SM9_WRAP_KEY, SM9_R_INVALID_POINTPPUB);
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
		SM9err(SM9_F_SM9_WRAP_KEY, ERR_R_SM9_LIB);
		goto end;
	}

	/* parse Q_B = H1(ID_B||hid) * P1 + Ppube */
	// we should check mpk->hash1
	if (!SM9_hash1(hash1_md, &h, id, id_len, SM9_HID_ENC, n, bn_ctx)
		|| !EC_POINT_mul(group, C, h, NULL, NULL, bn_ctx)
		|| !EC_POINT_add(group, C, C, Ppube, bn_ctx)) {
		ERR_print_errors_fp(stderr);
		SM9err(SM9_F_SM9_WRAP_KEY, ERR_R_EC_LIB);
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
