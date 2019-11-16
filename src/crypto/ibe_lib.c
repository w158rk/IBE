# include <openssl/sm9.h>

#include <crypto.h>
#include <utils.h>
#include <config.h>
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

int ibe_store_sP(EC_POINT *point, char *mpk_file)
{
	int ret = 0;
	if(!point)
	{
		ERROR("point used to store in the mpk is null");
		goto end;
	}

    SM9PublicParameters *sm9_mpk = NULL;

    FILE *mpk_fp = NULL;
	mpk_fp = fopen(mpk_file, "rb");
	if (!d2i_SM9PublicParameters_fp(mpk_fp, &sm9_mpk)){
		ERROR(" get mpk failed");
        goto end;
    }
    fclose(mpk_fp);

	char buff[BUFFER_SIZE];
	int length = BUFFER_SIZE;
	int point_form = POINT_CONVERSION_UNCOMPRESSED;
	EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_sm9bn256v1);
	BN_CTX *ctx = BN_CTX_new();

	length = EC_POINT_point2oct(group, point, point_form, buff, length, ctx);
	if(!length)
	{
		ERROR("can not convert the point to oct string");
        goto end;
	}

	// set the param
	sm9_mpk->pointPpub = ASN1_OCTET_STRING_new();
	if(!sm9_mpk->pointPpub)
	{
		ERROR("can not allocate for the ASN string");
        goto end;
	}

	if(!ASN1_OCTET_STRING_set(sm9_mpk->pointPpub, buff, length))
	{
		ERROR("can not set the pointPpub in sm9 mpk");
        goto end;
	}

	// output
    mpk_fp = fopen(mpk_file, "wb");
	if (!i2d_SM9PublicParameters_fp(mpk_fp, sm9_mpk)){
		ERROR(" output mpk failed");
        goto end;
    }
    fclose(mpk_fp);

	ret = 1;

end:
	EC_GROUP_free(group);
	BN_CTX_free(ctx);
	return ret;

}

int ibe_store_sQ(EC_POINT *sQ, ID *id, char *mpk_file)
{
	/* before this point, the file of the private key is not exist */
	/* so we generate a new SM9PrivateKey for it */
	int ret = 0;


	SM9PrivateKey *sk = NULL;
	EC_GROUP *group = NULL;
	const BIGNUM *p = SM9_get0_prime();
	const BIGNUM *n = SM9_get0_order();
	int scheme;
	unsigned char hid;
	const EVP_MD *md;
	BN_CTX *ctx = NULL;
	BIGNUM *t = NULL;
	int point_form = POINT_CONVERSION_UNCOMPRESSED;
	unsigned char buf[129];
	size_t len = sizeof(buf);

    SM9PublicParameters *sm9_mpk = NULL;
    FILE *mpk_fp = NULL;
	mpk_fp = fopen(mpk_file, "rb");
	if (!d2i_SM9PublicParameters_fp(mpk_fp, &sm9_mpk)){
		ERROR(" get mpk failed");
        goto end;
    }
    fclose(mpk_fp);

	/* check args */
	if (!id) {
		ERROR("id is null");
		return 0;
	}

	/* check scheme */
	scheme = OBJ_obj2nid(sm9_mpk->scheme);
	switch (scheme) {
	case NID_sm9sign:
		hid = SM9_HID_SIGN;
		break;
	case NID_sm9keyagreement:
		hid = SM9_HID_EXCH;
		break;
	case NID_sm9encrypt:
		hid = SM9_HID_ENC;
		break;
	default:
		return NULL;
	}

	/* check hash1 and set hash1 md */
	switch (OBJ_obj2nid(sm9_mpk->hash1)) {
	case NID_sm9hash1_with_sm3:
		md = EVP_sm3();
		break;
	case NID_sm9hash1_with_sha256:
		md = EVP_sha256();
		break;
	default:
		ERROR("hash1 is not set appropriately");
		return NULL;
	}


	/* malloc */
	if (!(sk = SM9PrivateKey_new())
		|| !(group = EC_GROUP_new_by_curve_name(NID_sm9bn256v1))
		|| !(ctx = BN_CTX_new())) {
		ERROR("cannot allocate for the params");
		goto end;
	}
	BN_CTX_start(ctx);

	if (!(sk->pairing = sm9_mpk->pairing)
		|| !(sk->scheme = sm9_mpk->scheme)
		|| !(sk->hash1 = sm9_mpk->hash1)
		|| !(sk->pointPpub = ASN1_OCTET_STRING_dup(sm9_mpk->pointPpub))
		|| !(sk->identity = ASN1_OCTET_STRING_new())
		|| !ASN1_OCTET_STRING_set(sk->identity, (unsigned char *)id->id, id->length)
		|| !(sk->publicPoint = ASN1_OCTET_STRING_new())
		|| !(sk->privatePoint = ASN1_OCTET_STRING_new())) {
		ERROR("cannot set the constant params of sk");
		goto end;
	}

	/* h1 = H1(id||HID) */
	if (!SM9_hash1(md, &t, id->id, id->length, hid, n, ctx)) {
		ERROR("error in hash");
		goto end;
	}

	{

		/* publicPoint = h1 * P1 + Ppube */
		EC_POINT *Ppube = NULL;
		EC_POINT *point = NULL;
		if (!(group = EC_GROUP_new_by_curve_name(NID_sm9bn256v1))
			|| !(point = EC_POINT_new(group))
			|| !(Ppube = EC_POINT_new(group))
			|| !EC_POINT_oct2point(group, Ppube,
				ASN1_STRING_get0_data(sm9_mpk->pointPpub),
				ASN1_STRING_length(sm9_mpk->pointPpub), ctx)
			|| !EC_POINT_mul(group, point, t, NULL, NULL, ctx)
			|| !EC_POINT_add(group, point, point, Ppube, ctx)
			|| !(len = EC_POINT_point2oct(group, point, point_form, buf, len, ctx))
			|| !ASN1_OCTET_STRING_set(sk->publicPoint, buf, len)) {
			ERROR("cannot get the new Q");
			EC_POINT_free(Ppube);
			EC_POINT_free(point);
			goto end;
		}
		EC_POINT_free(Ppube);
		EC_POINT_free(point);
	}

	{
		/* instead to use the s/(h+s)P, we use the s(h+s)P as the private key */
		
		/* de = t2 * P2 */
		char buffer[BUFFER_SIZE];
		int length = BUFFER_SIZE;
		length = EC_POINT_point2oct(group, sQ, point_form, buffer, length, ctx);

		if(!length)
		{
			ERROR("can not convert the point to oct string");
			goto end;
		}

		if(!ASN1_OCTET_STRING_set(sk->privatePoint, buffer, length))
		{
			ERROR("can not set the pointPpub in sm9 mpk");
			goto end;
		}

	}

	// output
	GENERATE_SK_FILENAME(id)
    FILE *sk_fp = fopen(filename, "wb");
	if (!i2d_SM9PublicParameters_fp(mpk_fp, sm9_mpk)){
		ERROR(" output mpk failed");
        goto end;
    }
    fclose(sk_fp);

	ret = 1;

end:
	SM9PrivateKey_free(sk);
	EC_GROUP_clear_free(group);
	if (ctx) {
		BN_CTX_end(ctx);
	}
	BN_CTX_free(ctx);
	BN_clear_free(t);
	OPENSSL_cleanse(buf, sizeof(buf));
	return ret;


}