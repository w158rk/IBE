/**
 * 
 * @file    ibe_ec
 * @brief   all the functions related to ec in ibe 
 * 
 */
#include <ds.h>
#include <config.h>
#include "smx_lcl.h"
#include "ibe_err.h"
#include "ibe_lcl.h"

int ibe_get_group_id()
{
    return NID_sm9bn256v1; 
}

EC_GROUP *ibe_get_ec_group()
{
    return EC_GROUP_new_by_curve_name(NID_sm9bn256v1);
}

char *ibe_ec2str(EC_POINT *point, BN_CTX* ctx)
{
    return EC_POINT_point2hex(ibe_get_ec_group(), point, POINT_CONVERSION_COMPRESSED, ctx);

}

EC_POINT *ibe_str2ec(char *str, EC_POINT *point, BN_CTX *ctx)
{
	return EC_POINT_hex2point(ibe_get_ec_group(), str, point, ctx);
}

EC_POINT *ibe_EC_POINT_new()
{
	return EC_POINT_new(ibe_get_ec_group());

}

int ibe_ec_cal_xP1(EC_GROUP **group_ptr, EC_POINT **point, BIGNUM *x, char *mpk_file)
{

    int ret = 0;
	if(*point != NULL || *group_ptr != NULL)
	{
		ERROR(MEM_POINTER_NOT_NULL_ERROR);
		goto end;
	}

    // read the mpk from file 

	EC_GROUP *group = NULL;
	EC_POINT *C = NULL;
	BN_CTX *bn_ctx = NULL;

	/** allocate the spaces */

	if (!(group = EC_GROUP_new_by_curve_name(NID_sm9bn256v1))
		|| !(C = EC_POINT_new(group))
		|| !(bn_ctx = BN_CTX_new())) {
		
		ERROR(MEM_ALLOC_ERROR);
		goto end;
	}

	BN_CTX_start(bn_ctx);

    // calculate C = xP
	if (!EC_POINT_mul(group, C, x, NULL, NULL, bn_ctx)) {
		ERROR(EC_CAL_ERROR);
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


char *ibe_ec_cal_xP1_py(char *x_str, char *mpk_file)
{
	BIGNUM *x = NULL;
	BN_str2bn(&x, x_str);
	BN_CTX *ctx = BN_CTX_new();
	EC_GROUP *group = NULL;
	EC_POINT *point = NULL;
	char *ret = NULL;

	if (!ibe_ec_cal_xP1(&group, &point, x, mpk_file))
	{
		goto end;
	}

	ret = ibe_ec2str(point, ctx);

end:
	BN_free(x);
	BN_CTX_free(ctx);
	return ret;
	
}

int ibe_ec_cal_xQ(EC_GROUP **group_ptr, EC_POINT **point, BIGNUM *x, EC_POINT *Q, char *mpk_file)
{

    int ret = 0;
	if(*point != NULL || *group_ptr != NULL)
	{
		ERROR(MEM_POINTER_NOT_NULL_ERROR);
		goto end;
	}

    // read the mpk from file 

    SMXPublicParameters *smx_mpk = NULL;
	
	{
		FILE *mpk_fp = fopen(mpk_file, "rb");
		if (!d2i_SMXPublicParameters_fp(mpk_fp, &smx_mpk)){
			ERROR_WITH_STR(MPK_FROM_FILE_ERROR, mpk_file);
			goto end;
		}
	    fclose(mpk_fp);
	}    

	EC_GROUP *group = NULL;
	EC_POINT *C = NULL;
	BN_CTX *bn_ctx = NULL;
	const BIGNUM *n = SMX_get0_order();

	/** allocate the spaces */
	if (!(group = EC_GROUP_new_by_curve_name(NID_sm9bn256v1))
		|| !(C = EC_POINT_new(group))
		|| !(bn_ctx = BN_CTX_new())) {
		
		ERROR(MEM_ALLOC_ERROR);
		goto end;
	}

	BN_CTX_start(bn_ctx);

    // calculate C = xQ
	if (!EC_POINT_mul(group, C, NULL, Q, x, bn_ctx)) {
		ERROR(EC_CAL_ERROR);
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

int ibe_ec_store_Ppub1(EC_POINT *point, char *mpk_file)
{
	int ret = 0;
	if(!point)
	{
		ERROR(MEM_POINTER_NULL_ERROR);
		goto end;
	}

    SMXPublicParameters *smx_mpk = NULL;
	
	{
		FILE *mpk_fp = NULL;
		if ((mpk_fp = fopen(mpk_file, "rb")) != NULL){

			if (!d2i_SMXPublicParameters_fp(mpk_fp, &smx_mpk)){
				ERROR(MPK_FROM_FILE_ERROR);
				return 0;
			}
			fclose(mpk_fp);

		}

	}
	
	char buff[BUFFER_SIZE];
	int length = BUFFER_SIZE;
	int point_form = POINT_CONVERSION_UNCOMPRESSED;
	EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_sm9bn256v1);
	BN_CTX *ctx = BN_CTX_new();

	length = EC_POINT_point2oct(group, point, point_form, buff, length, ctx);
	if(!length)
	{
		ERROR(EC_TO_STR_ERROR);
        goto end;
	}

	// set the param
	if(smx_mpk->pointPpub1)
	{
		ASN1_OCTET_STRING_free(smx_mpk->pointPpub1);
		smx_mpk->pointPpub1 = NULL;
	}

	smx_mpk->pointPpub1 = ASN1_OCTET_STRING_new();
	if(!smx_mpk->pointPpub1)
	{
		ERROR(MEM_ALLOC_ERROR);
        goto end;
	}

	if(!ASN1_OCTET_STRING_set(smx_mpk->pointPpub1, buff, length))
	{
		ERROR(MPK_SET_MEMBER_ERROR);
        goto end;
	}

#ifdef DEBUG
{
	char data[10] = "1234567890";
	char cipher[BUFFER_SIZE] = {0};
	int datalen = 10;
	int cipherlen = BUFFER_SIZE;
	fprintf(stderr, "encrypt: %d\n", SMX_encrypt(NID_sm9encrypt_with_sm3_xor, data, datalen, cipher, &cipherlen, smx_mpk, "Server", 6));

}
#endif

	{	// output
		FILE *mpk_fp = NULL;
		mpk_fp = fopen(mpk_file, "wb");
		if (!i2d_SMXPublicParameters_fp(mpk_fp, smx_mpk)){
			ERROR_WITH_STR(MPK_TO_FILE_ERROR, mpk_file);
			goto end;
		}
		fclose(mpk_fp);
	}

	ret = 1;

end:
	EC_GROUP_free(group);
	BN_CTX_free(ctx);
	return ret;

}

int ibe_ec_store_sk(EC_POINT *sQ, ID *id, char *mpk_file, char *sk_file)
{
	/* before this point, the file of the private key is not exist */
	/* so we generate a new SMXPrivateKey for it */
	int ret = 0;


	SMXPrivateKey *sk = NULL;
	EC_GROUP *group = NULL;
	const BIGNUM *p = SMX_get0_prime();
	const BIGNUM *n = SMX_get0_order();
	int scheme;
	unsigned char hid;
	const EVP_MD *md;
	BN_CTX *ctx = NULL;
	BIGNUM *t = NULL;
	int point_form = POINT_CONVERSION_UNCOMPRESSED;
	unsigned char buf[129];
	size_t len = sizeof(buf);

    SMXPublicParameters *smx_mpk = NULL;

	{
		FILE *mpk_fp = NULL;
		mpk_fp = fopen(mpk_file, "rb");
		if (!d2i_SMXPublicParameters_fp(mpk_fp, &smx_mpk)){
			ERROR_WITH_STR(MPK_FROM_FILE_ERROR, mpk_file);
			goto end;
		}
		fclose(mpk_fp);
	}

	/* check args */
	if (!id) {
		ERROR(MEM_POINTER_NULL_ERROR);
		return 0;
	}

	/* check scheme */
	scheme = OBJ_obj2nid(smx_mpk->scheme);
	switch (scheme) {
	case NID_sm9sign:
		hid = SMX_HID_SIGN;
		break;
	case NID_sm9keyagreement:
		hid = SMX_HID_EXCH;
		break;
	case NID_sm9encrypt:
		hid = SMX_HID_ENC;
		break;
	default:
		return 0;
	}

	/* check hash1 and set hash1 md */
	switch (OBJ_obj2nid(smx_mpk->hash1)) {
	case NID_sm9hash1_with_sm3:
		md = EVP_sm3();
		break;
	case NID_sm9hash1_with_sha256:
		md = EVP_sha256();
		break;
	default:
		ERROR(OPENSSL_HASH_ERROR);
		return 0;
	}


	/* malloc */
	if (!(sk = SMXPrivateKey_new())
		|| !(group = EC_GROUP_new_by_curve_name(NID_sm9bn256v1))
		|| !(ctx = BN_CTX_new())) {
		ERROR(MEM_ALLOC_ERROR);
		goto end;
	}
	BN_CTX_start(ctx);

	if (!(sk->pairing = smx_mpk->pairing)
		|| !(sk->scheme = smx_mpk->scheme)
		|| !(sk->hash1 = smx_mpk->hash1)
		|| !(sk->pointPpub1 = ASN1_OCTET_STRING_dup(smx_mpk->pointPpub1))
		|| !(sk->pointPpub2 = ASN1_OCTET_STRING_dup(smx_mpk->pointPpub2))
		|| !(sk->identity = ASN1_OCTET_STRING_new())
		|| !ASN1_OCTET_STRING_set(sk->identity, (unsigned char *)id->id, id->length)
		|| !(sk->publicPoint = ASN1_OCTET_STRING_new())
		|| !(sk->privatePoint = ASN1_OCTET_STRING_new())) {
		ERROR(SK_SET_MEMBER_ERROR);
		goto end;
	}

	/* h1 = H1(id||HID) */
	if (!SMX_hash1(md, &t, id->id, id->length, hid, n, ctx)) {
		ERROR(OPENSSL_HASH_ERROR);
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
				ASN1_STRING_get0_data(smx_mpk->pointPpub1),
				ASN1_STRING_length(smx_mpk->pointPpub1), ctx)
			|| !EC_POINT_mul(group, point, t, NULL, NULL, ctx)
			|| !EC_POINT_add(group, point, point, Ppube, ctx)
			|| !(len = EC_POINT_point2oct(group, point, point_form, buf, len, ctx))
			|| !ASN1_OCTET_STRING_set(sk->publicPoint, buf, len)) {
			ERROR(EC_FROM_STR_ERROR);
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
			ERROR(POINT_TO_STR_ERROR);
			goto end;
		}

		if(!ASN1_OCTET_STRING_set(sk->privatePoint, buffer, length))
		{
			ERROR(MPK_SET_MEMBER_ERROR);
			goto end;
		}

	}

		// try encrypt and decrypt with the given keys 
#ifdef DEBUG
{
	char data[10] = "1234567890";
	char cipher[BUFFER_SIZE] = {0};
	char ddata[BUFFER_SIZE] = {0};
	int datalen = 10;
	int cipherlen = BUFFER_SIZE;
	int ddata_len = BUFFER_SIZE;
	fprintf(stderr, "encrypt: %d\n", SMX_encrypt(NID_sm9encrypt_with_sm3_xor, data, datalen, cipher, &cipherlen, smx_mpk, "Client", 6));
	fprintf(stderr, "decrypt: %d\n", SMX_decrypt(NID_sm9encrypt_with_sm3_xor, cipher, cipherlen, ddata, &ddata_len, sk));
	fprintf(stderr, "encrypt: %d\n", SMX_encrypt(NID_sm9encrypt_with_sm3_xor, data, datalen, cipher, &cipherlen, smx_mpk, "Server", 6));
	fprintf(stderr, "decrypt: %d\n", SMX_decrypt(NID_sm9encrypt_with_sm3_xor, cipher, cipherlen, ddata, &ddata_len, sk));

}
#endif

	// output
	{
		FILE *sk_fp = fopen(sk_file, "wb");
		if (!i2d_SMXPrivateKey_fp(sk_fp, sk)){
			ERROR(SK_TO_FILE_ERROR);
			goto end;
		}
		fclose(sk_fp);
	}

	ret = 1;

end:
	SMXPrivateKey_free(sk);
	EC_GROUP_clear_free(group);
	if (ctx) {
		BN_CTX_end(ctx);
	}
	BN_CTX_free(ctx);
	BN_clear_free(t);
	OPENSSL_cleanse(buf, sizeof(buf));
	return ret;


}

/*  the caller should ensure that mpk_file end with '\0' */
/* parse Q_B = H1(ID_B||hid) * P1 + Ppub1 */
int ibe_ec_id2point(
    EC_POINT **point,    
    char *id, 
    long id_len,
    char *mpk_file
) 
{
	int ret = 0;
	if(*point != NULL)
	{
		ERROR(MEM_POINTER_NOT_NULL_ERROR);
		return 0;
	}

    // read the mpk from file 

    SMXPublicParameters *smx_mpk = NULL;

	{    
		FILE *mpk_fp = fopen(mpk_file, "rb");
		if (!d2i_SMXPublicParameters_fp(mpk_fp, &smx_mpk)){
			ERROR(MPK_FROM_FILE_ERROR);
			return 0;
		}
		fclose(mpk_fp);
	}
	
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
		
		ERROR(MEM_ALLOC_ERROR);
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
		ERROR(OPENSSL_HASH_ERROR);
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
		ERROR(EC_CAL_ERROR);
		goto end;
	}

	*point = C;
	ret = 1;

end:
	if (bn_ctx) {
		BN_CTX_end(bn_ctx);
	}
	BN_free(h);
	BN_CTX_free(bn_ctx);
	return ret;
    
}

/*  the caller should ensure that mpk_file end with '\0' */
/* parse Q_B = H1(ID_B||hid) * P1*/
int ibe_ec_id2point_common(
    EC_POINT **point,    
    char *id, 
    long id_len,
	char *mpk_file
) 
{

	int ret = 0;
	if(*point != NULL)
	{
		ERROR(MEM_POINTER_NOT_NULL_ERROR);
		return 0;
	}

    // read the mpk from file 

    SMXPublicParameters *smx_mpk = NULL;

	{    
		FILE *mpk_fp = fopen(mpk_file, "rb");
		if (!d2i_SMXPublicParameters_fp(mpk_fp, &smx_mpk)){
			ERROR(MPK_FROM_FILE_ERROR);
			return 0;
		}
		fclose(mpk_fp);
	}
	
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
		
		ERROR(MEM_ALLOC_ERROR);
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
		ERROR(OPENSSL_HASH_ERROR);
		goto end;
	}


	/* parse Q_B = H1(ID_B||hid) * P1 */
	// we should check mpk->hash1
	if (!SMX_hash1(hash1_md, &h, id, id_len, SMX_HID_ENC, n, bn_ctx)
		|| !EC_POINT_mul(group, C, h, NULL, NULL, bn_ctx))
	{
		ERROR(EC_CAL_ERROR);
		goto end;
	}

	*point = C;
	ret = 1;

end:
	if (bn_ctx) {
		BN_CTX_end(bn_ctx);
	}
	BN_free(h);
	BN_CTX_free(bn_ctx);
	return ret;
    
}

