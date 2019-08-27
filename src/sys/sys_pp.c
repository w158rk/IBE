// /**
//  * @file sys_pp.c
//  * @author Wang Ruikai 
//  * @date August 8th, 2019 
//  * @brief functions to get public parameters
//  */

// #include <sys.h>
// #include <openssl/sm9.h>
// #include <openssl/err.h>

// int sys_getGroupGen(EC_POINT **point)
// {

// 	int ret = 0;
// 	EC_GROUP *group = NULL;
// 	EC_POINT *C = NULL;

// 	if (!(group = EC_GROUP_new_by_curve_name(NID_sm9bn256v1))
// 		|| !(C = EC_POINT_new(group))
// 		|| !(EC_POINT_copy(C, group->generator))) {
// 		SM9err(SM9_F_SM9_WRAP_KEY, ERR_R_MALLOC_FAILURE);
// 		goto end;
// 	}

// 	*point = C;
// 	ret = 1;

// end:

// 	EC_GROUP_free(group);
// 	return ret;
// }

// int sys_getPointPpub(
//     EC_POINT **point, 
//     IBEPublicParameters *mpk,
//     size_t mpk_len)
// {

// 	int ret = 0;
// 	EC_GROUP *group = NULL;
// 	EC_POINT *Ppube = NULL;
//     BN_CTX *bn_ctx = NULL;

// 	if (!(group = EC_GROUP_new_by_curve_name(NID_sm9bn256v1))
// 		|| !(Ppube = EC_POINT_new(group))
// 		|| !(bn_ctx = BN_CTX_new())) {
// 		SM9err(SM9_F_SM9_WRAP_KEY, ERR_R_MALLOC_FAILURE);
// 		goto end;
// 	}

//     SM9PublicParameters *sm9_mpk = NULL;
//     d2i_SM9PublicParameters(&sm9_mpk, mpk, mpk_len);

// 	/* parse Ppube */
// 	if (!EC_POINT_oct2point(group, Ppube, ASN1_STRING_get0_data(sm9_mpk->pointPpub),
// 		ASN1_STRING_length(sm9_mpk->pointPpub), bn_ctx)) {
// 		SM9err(SM9_F_SM9_WRAP_KEY, SM9_R_INVALID_POINTPPUB);
// 		goto end;
// 	}

// 	*point = Ppube;
// 	ret = 1;

// end:
// 	EC_GROUP_free(group);
// 	EC_POINT_free(Ppube);
// 	if (bn_ctx) {
// 		BN_CTX_end(bn_ctx);
// 	}
// 	BN_CTX_free(bn_ctx);
// 	return ret;
// }
