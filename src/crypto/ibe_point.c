/**
 * 
 * @file ibe_id2point.c
 * @brief all functions related to the operations in G2
 *
 */

#include <crypto.h>
#include <config.h>

#include "smx_lcl.h"
#include "ibe_err.h"



int ibe_point_to_octets(point_t *point, char *buf)
{
	int rtn = 0;

	if(!point || !buf)
	{
		ERROR(MEM_POINTER_NULL_ERROR);
		return 0;
	}

	BN_CTX *bn_ctx = BN_CTX_new();
	BN_CTX_start(bn_ctx);

#ifdef DEBUG 
{
	const BIGNUM *p = SMX_get0_prime();
	if(!point_is_on_curve_smx(point, p, bn_ctx))
	{
		ERROR(POINT_NOT_IN_GROUP_ERROR);
	}
	
}
#endif

	if(!point_to_octets_smx(point, buf, bn_ctx))
	{
		ERROR(POINT_TO_STR_ERROR);
		goto end;
	}

#ifdef DEBUG 
{
	const BIGNUM *p = SMX_get0_prime();
	point_t dbg_point;

	if(!point_init_smx(&dbg_point, bn_ctx)
		|| !point_from_octets_smx(&dbg_point, buf, p, bn_ctx))
	{
		ERROR(POINT_TO_STR_ERROR);
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
		ERROR(MEM_POINTER_NOT_NULL_ERROR);
		return 0;
	}

	const BIGNUM *p = SMX_get0_prime();
	point_t *res = (point_t *)malloc(sizeof(point_t));
	BN_CTX *bn_ctx = BN_CTX_new();
	BN_CTX_start(bn_ctx);

	if(!point_init_smx(res, bn_ctx)
		||!point_from_octets_smx(res, buf, p, bn_ctx))
	{
		ERROR(POINT_FROM_STR_ERROR);
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
		ERROR(POINT_CAL_ERROR);
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

int ibe_point_is_on_curve(point_t *point)
{
	if(!point)
	{
		return 0;
	}

	int ret = 0;
	const BIGNUM *p = SMX_get0_prime();
	BN_CTX *bn_ctx = NULL;
	if(!(bn_ctx = BN_CTX_new()))
	{
		ERROR(MEM_ALLOC_ERROR);
		goto end;
	}

	BN_CTX_start(bn_ctx);

	ret = point_is_on_curve_smx(point, p, bn_ctx);

end:
	if (bn_ctx) {
		BN_CTX_end(bn_ctx);
	}
	BN_CTX_free(bn_ctx);
	return ret;
}

int ibe_point_cal_xP2(point_t *res, BIGNUM *x, char *mpk_file)
{

    int ret = 0;
	point_t point;

	BN_CTX *bn_ctx = NULL;
	const BIGNUM *p = SMX_get0_prime();

	/** allocate the spaces */
	if(!(bn_ctx = BN_CTX_new()))
	{
		ERROR(MEM_ALLOC_ERROR);
		goto end;
	}

	BN_CTX_start(bn_ctx);

    // calculate C = xP
	if (!point_init_smx(&point, bn_ctx)
		||!point_mul_smx_generator(&point, x, p, bn_ctx)
		||!point_is_on_curve_smx(&point, p, bn_ctx)) {
		ERROR(POINT_CAL_ERROR);
		goto end;
	}

	point_copy_smx(res, &point);

#ifdef DEBUG 
	if(!point_is_on_curve_smx(res, p, bn_ctx))
	{
		ERROR(POINT_NOT_IN_GROUP_ERROR);
	}
	if(!point_is_on_curve_smx(res, p, bn_ctx))
	{
		ERROR(POINT_NOT_IN_GROUP_ERROR);
	}
#endif

	ret = 1;

end:
	if (bn_ctx) {
		BN_CTX_end(bn_ctx);
	}
	// this free will make the res not work 
	// but how to free the ctx safely is unknown so far 
	// BN_CTX_free(bn_ctx);
	return ret;

}






int ibe_point_store_Ppub2(point_t *point, char *mpk_file)
{
	int ret = 0;
	if(!point)
	{
		ERROR(MEM_POINTER_NULL_ERROR);
		goto end;
	}

    SMXPublicParameters *smx_mpk = NULL;

    FILE *mpk_fp = NULL;
	char buff[BUFFER_SIZE];
	int flag = 0;
	BN_CTX* ctx = BN_CTX_new();

	mpk_fp = fopen(mpk_file, "rb");
	if (!d2i_SMXPublicParameters_fp(mpk_fp, &smx_mpk)){
		ERROR(MPK_FROM_FILE_ERROR);
        goto end;
    }
    fclose(mpk_fp);


	if(!point_to_octets_smx(point, buff, ctx))
	{
		ERROR(POINT_TO_STR_ERROR);
        goto end;
	}
	int length = 129;

	// set the param
	smx_mpk->pointPpub2 = ASN1_OCTET_STRING_new();
	if(!smx_mpk->pointPpub2)
	{
		ERROR(MEM_ALLOC_ERROR);
        goto end;
	}

	if(!ASN1_OCTET_STRING_set(smx_mpk->pointPpub2, buff, length))
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

	// output
    mpk_fp = fopen(mpk_file, "wb");
	if (!i2d_SMXPublicParameters_fp(mpk_fp, smx_mpk)){
		ERROR(MPK_TO_FILE_ERROR);
        goto end;
    }
    fclose(mpk_fp);

	ret = 1;

end:
	BN_CTX_free(ctx);
	return ret;

}