#include <crypto.h>

#include <openssl/sm9.h>
#include<openssl/err.h>
#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <string.h>
#include <openssl/sm9_lcl.h>
//#include "sm9_lcl.h"

int ibe_sign(const unsigned char *data, size_t data_length, const unsigned char* sign, size_t *sign_length, SM9PrivateKey *sk)
{
    int ret = -1;
	printf("Here");
	printf("data in sign is%s\n", data);
    printf("sk is sign is%s\n", sk);
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
	char *sk_data = (char *)malloc(313);
	memcpy(sk_data, sk, 313);
	printf("data is%s\n", sk_data);
	//printf("sk is%s\n", sk);
	
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

	SM9_SignInit(ctx, md, NULL);
	printf("HERE\n");
	SM9_SignUpdate(ctx, data, datalen);
	printf("HERE\n");
	// printf("ctx is%s\n", ctx);
	// printf("sk is%s\n", sk);
	printf("ctx is%s\n", ctx);
	printf("data is%s\n", sk_data);
	sm9sig = SM9_SignFinal(ctx, sk_data);
	printf("sm9sig is%s\n", sm9sig);
	/*if (!SM9_SignInit(ctx, md, NULL)
		|| !SM9_SignUpdate(ctx, data, datalen)
		|| !(sm9sig = SM9_SignFinal(ctx, sk))) {
		SM9err(SM9_F_SM9_SIGN, ERR_R_SM9_LIB);
		goto end;
	}*/

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

SM9Signature *SM9_SignFinal(EVP_MD_CTX *ctx1, SM9PrivateKey *sk)
{
	SM9Signature *ret = NULL;
	SM9Signature *sig = NULL;
	const BIGNUM *p = SM9_get0_prime();
	const BIGNUM *n = SM9_get0_order();
	int point_form = POINT_CONVERSION_COMPRESSED;
	/* buf for w and prefix zeros of ct1/2 */
	unsigned char buf[384] = {0};
	unsigned int len;
	const unsigned char ct1[4] = {0x00, 0x00, 0x00, 0x01};
	const unsigned char ct2[4] = {0x00, 0x00, 0x00, 0x02};
	EVP_MD_CTX *ctx2 = NULL;
	EC_GROUP *group = NULL;
	EC_POINT *S = NULL;
	BN_CTX *bn_ctx = NULL;
	BIGNUM *r = NULL;
	point_t Ppubs;
	fp12_t w;

	if (!(sig = SM9Signature_new())
		|| !(ctx2 = EVP_MD_CTX_new())
		|| !(group = EC_GROUP_new_by_curve_name(NID_sm9bn256v1))
		|| !(S = EC_POINT_new(group))
		|| !(bn_ctx = BN_CTX_new())) {
		SM9err(SM9_F_SM9_SIGNFINAL, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	BN_CTX_start(bn_ctx);
	if (!(r = BN_CTX_get(bn_ctx))
		|| !fp12_init(w, bn_ctx)
		|| !point_init(&Ppubs, bn_ctx)) {
		SM9err(SM9_F_SM9_SIGNFINAL, ERR_R_MALLOC_FAILURE);
		goto end;
	}
// 	printf("sk in sign is%s\n",sk);

	/* get Ppubs */
	if (ASN1_STRING_length(sk->pointPpub) != 129
		|| !point_from_octets(&Ppubs, ASN1_STRING_get0_data(sk->pointPpub), p, bn_ctx)) {
		SM9err(SM9_F_SM9_SIGNFINAL, SM9_R_INVALID_POINTPPUB);
		goto end;
	}
	/* g = e(P1, Ppubs) */
	if (!rate_pairing(w, &Ppubs, EC_GROUP_get0_generator(group), bn_ctx)) {
		SM9err(SM9_F_SM9_SIGNFINAL, SM9_R_PAIRING_ERROR);
		goto end;
	}

	do {
		/* r = rand(1, n - 1) */
		do {
			if (!BN_rand_range(r, n)) {
				SM9err(SM9_F_SM9_SIGNFINAL, ERR_R_BN_LIB);
				goto end;
			}
		} while (BN_is_zero(r));

		/* w = g^r */
		if (!fp12_pow(w, w, r, p, bn_ctx)
			|| !fp12_to_bin(w, buf)) {
			SM9err(SM9_F_SM9_SIGNFINAL, SM9_R_EXTENSION_FIELD_ERROR);
			goto end;
		}

		if (!EVP_DigestUpdate(ctx1, buf, sizeof(buf))
			|| !EVP_MD_CTX_copy(ctx2, ctx1)
			/* Ha1 = Hv(0x02||M||w||0x00000001) */
			|| !EVP_DigestUpdate(ctx1, ct1, sizeof(ct1))
		 	/* Ha2 = Hv(0x02||M||w||0x00000002) */
			|| !EVP_DigestUpdate(ctx2, ct2, sizeof(ct2))
			|| !EVP_DigestFinal_ex(ctx1, buf, &len)
			|| !EVP_DigestFinal_ex(ctx2, buf + len, &len)) {
			SM9err(SM9_F_SM9_SIGNFINAL, SM9_R_DIGEST_FAILURE);
			goto end;
		}

		/* Ha = Ha1||Ha2[0..7] */
		if (!BN_bin2bn(buf, 40, sig->h)
			/* h = (Ha mod (n - 1)) + 1 */
			|| !BN_mod(sig->h, sig->h, SM9_get0_order_minus_one(), bn_ctx)
			|| !BN_add_word(sig->h, 1)
			/* l = r - h (mod n) */
			|| !BN_mod_sub(r, r, sig->h, n, bn_ctx)) {
			SM9err(SM9_F_SM9_SIGNFINAL, ERR_R_BN_LIB);
			goto end;
		}
	} while (BN_is_zero(r));

	/* get sk */
	if (!EC_POINT_oct2point(group, S, ASN1_STRING_get0_data(sk->privatePoint),
		ASN1_STRING_length(sk->privatePoint), bn_ctx)) {
		SM9err(SM9_F_SM9_SIGNFINAL, SM9_R_INVALID_PRIVATE_POINT);
		goto end;
	}
	/* S = l * sk */
	len = sizeof(buf);
	if (!EC_POINT_mul(group, S, NULL, S, r, bn_ctx)
		|| !(len = EC_POINT_point2oct(group, S, point_form, buf, len, bn_ctx))
		|| !ASN1_OCTET_STRING_set(sig->pointS, buf, len)) {
		SM9err(SM9_F_SM9_SIGNFINAL, ERR_R_EC_LIB);
		goto end;
	}

	ret = sig;
	sig = NULL;

end:
	// SM9Signature_free(sig);
	// EVP_MD_CTX_free(ctx2);
	// EC_GROUP_free(group);
	// EC_POINT_free(S);
	// BN_free(r);
	// point_cleanup(&Ppubs);
	// fp12_cleanup(w);
	// BN_CTX_end(bn_ctx);
	// BN_CTX_free(bn_ctx);
	return ret;
}