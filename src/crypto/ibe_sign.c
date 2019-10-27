#include <crypto.h>

#include <openssl/sm9.h>
#include<openssl/err.h>
#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
//#include "sm9_lcl.h"

int ibe_sign(const unsigned char*data, size_t data_length, const unsigned char* sign, size_t *sign_length, SM9PrivateKey *sk)
{
    int ret = -1;
    ret = SM9_sign(NID_sm3, data, data_length, sign, sign_length, sk);
    return ret;
}

int ibe_verify(const unsigned char* data, size_t data_length, const unsigned char *sign, size_t sign_length, SM9PublicParameters *mpk, const char *id, size_t id_length)
{
    int ret = -1;
    ret = SM9_verify(NID_sm3, data, data_length, sign, sign_length, mpk, id, id_length);
    return ret;
}

int SM9_sign(int type, /* NID_[sm3 | sha256] */
	const unsigned char *data, size_t datalen,
	unsigned char *sig, size_t *siglen,
	SM9PrivateKey *sk)
{
	int ret = 0;
	EVP_MD_CTX *ctx = NULL;
	SM9Signature *sm9sig = NULL;
	const EVP_MD *md;
	int len;

	if (!(md = EVP_get_digestbynid(type))
		|| EVP_MD_size(md) != EVP_MD_size(EVP_sm3())) {
		SM9err(SM9_F_SM9_SIGN, SM9_R_INVALID_HASH2_DIGEST);
		return 0;
	}

	if (!(ctx = EVP_MD_CTX_new())) {
		SM9err(SM9_F_SM9_SIGN, ERR_R_MALLOC_FAILURE);
		return 0;
	}

	if (!SM9_SignInit(ctx, md, NULL)
		|| !SM9_SignUpdate(ctx, data, datalen)
		|| !(sm9sig = SM9_SignFinal(ctx, sk))) {
		SM9err(SM9_F_SM9_SIGN, ERR_R_SM9_LIB);
		goto end;
	}

	if ((len = i2d_SM9Signature(sm9sig, &sig)) <= 0) {
		SM9err(SM9_F_SM9_SIGN, ERR_R_SM9_LIB);
		goto end;
	}

	*siglen = len;
	ret = 1;

end:
	EVP_MD_CTX_free(ctx);
	SM9Signature_free(sm9sig);
	return ret;
}
