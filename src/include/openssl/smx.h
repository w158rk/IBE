/* ====================================================================
 * Copyright (c) 2016 - 2018 The GmSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the GmSSL Project.
 *    (http://gmssl.org/)"
 *
 * 4. The name "GmSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    guanzhi1980@gmail.com.
 *
 * 5. Products derived from this software may not be called "GmSSL"
 *    nor may "GmSSL" appear in their names without prior written
 *    permission of the GmSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the GmSSL Project
 *    (http://gmssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE GmSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE GmSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */

#ifndef HEADER_SMX_H
#define HEADER_SMX_H

#include <openssl/opensslconf.h>
#ifndef OPENSSL_NO_SMX

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/asn1.h>

/* set the same value as sm2 */
#define SMX_MAX_ID_BITS		65535
#define SMX_MAX_ID_LENGTH	(SMX_MAX_ID_BITS/8)

#ifdef __cplusplus
extern "C" {
#endif

typedef struct SMX_MASTER_KEY_st SMX_MASTER_KEY;
typedef struct SMX_KEY_st SMX_KEY;
typedef struct SMXSignature_st SMXSignature;
typedef struct SMXCiphertext_st SMXCiphertext;

typedef SMX_MASTER_KEY SMXMasterSecret;
typedef SMX_MASTER_KEY SMXPublicParameters;
typedef SMX_KEY SMXPrivateKey;
typedef SMX_KEY SMXPublicKey;

SMX_MASTER_KEY *SMX_MASTER_KEY_new(void);
void SMX_MASTER_KEY_free(SMX_MASTER_KEY *a);
SMX_KEY *SMX_KEY_new(void);
void SMX_KEY_free(SMX_KEY *a);

int SMX_MASTER_KEY_up_ref(SMX_MASTER_KEY *msk);
int SMX_KEY_up_ref(SMX_KEY *sk);

int SMX_setup(int pairing, /* NID_smxbn256v1 */
	int scheme, /* NID_[smxsign | smxencrypt | smxkeyagreement] */
	int hash1, /* NID_smxhash1_with_[sm3 | sha256] */
	SMXPublicParameters **mpk,
	SMXMasterSecret **msk);

SMXMasterSecret *SMX_generate_master_secret(int pairing, int scheme, int hash1);
SMXPublicParameters *SMX_extract_public_parameters(SMXMasterSecret *msk);
SMXPrivateKey *SMX_extract_private_key(SMXMasterSecret *msk,
	const char *id, size_t idlen);
SMXPublicKey *SMX_extract_public_key(SMXPublicParameters *mpk,
	const char *id, size_t idlen);

SMXPublicKey *SMXPrivateKey_get_public_key(SMXPrivateKey *sk);

int SMXPrivateKey_get_gmtls_public_key(SMXPublicParameters *mpk,
	SMXPrivateKey *sk, unsigned char pub_key[1024]);

int SMXPublicKey_get_gmtls_encoded(SMXPublicParameters *mpk,
	SMXPublicKey *pk, unsigned char encoded[1024]);

int SMX_signature_size(const SMXPublicParameters *mpk);

SMXSignature *SMX_do_sign(const unsigned char *dgst, int dgstlen, SMX_KEY *smx);
int SMX_do_verify(const unsigned char *dgst, int dgstlen,
	const SMXSignature *sig, SMX_KEY *smx);

int SMX_sign(int type,
	const unsigned char *data, size_t datalen,
	unsigned char *sig, size_t *siglen,
	SMXPrivateKey *sk);

int SMX_verify(int type,
	const unsigned char *data, size_t datalen,
	const unsigned char *sig, size_t siglen,
	SMXPublicParameters *mpk, const char *id, size_t idlen);

int SMX_SignInit(EVP_MD_CTX *ctx, const EVP_MD *md, ENGINE *engine);
#define SMX_SignUpdate(ctx,d,l) EVP_DigestUpdate(ctx,d,l)
SMXSignature *SMX_SignFinal(EVP_MD_CTX *ctx, SMXPrivateKey *sk);

int SMX_VerifyInit(EVP_MD_CTX *ctx, const EVP_MD *md, ENGINE *engine);
#define SMX_VerifyUpdate(ctx,d,l) EVP_DigestUpdate(ctx,d,l)
int SMX_VerifyFinal(EVP_MD_CTX *ctx, const SMXSignature *sig, SMXPublicKey *pk);

int SMX_wrap_key(int type, /* NID_smxkdf_with_sm3 */
	unsigned char *key, size_t keylen,
	unsigned char *enced_key, size_t *enced_len,
	SMXPublicParameters *mpk, const char *id, size_t idlen);

int SMX_unwrap_key(int type,
	unsigned char *key, size_t keylen,
	const unsigned char *enced_key, size_t enced_len,
	SMXPrivateKey *sk);

int SMX_ciphertext_size(const SMX_MASTER_KEY *params, size_t inlen);

int SMX_encrypt(int type, /* NID_smxencrypt_with_sm3_xor */
	const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen,
	SMXPublicParameters *mpk, const char *id, size_t idlen);

int SMX_decrypt(int type,
	const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen,
	SMXPrivateKey *sk);

/* the key agreement API might be changed */
int SMX_generate_key_exchange(unsigned char *R, size_t *Rlen, /* R = r * Q_ID */
	BIGNUM *r, unsigned char *gr, size_t *grlen, /* gr = e(Ppube, P2)^r */
	const char *peer_id, size_t peer_idlen, /* peer's identity */
	SMXPrivateKey *sk, int initiator);

int SMX_compute_share_key_A(int type,
	unsigned char *SKA, size_t SKAlen,
	unsigned char SA[32], /* optional, send to B */
	const unsigned char SB[32], /* optional, recv from B */
	const BIGNUM *rA,
	const unsigned char RA[65],
	const unsigned char RB[65],
	const unsigned char g1[384],
	const char *IDB, size_t IDBlen,
	SMXPrivateKey *skA);

int SMX_compute_share_key_B(int type,
	unsigned char *SKB, size_t SKBlen,
	unsigned char SB[32], /* optional, send to A */
	unsigned char S2[32], /* optional, to be compared with recved SA */
	const BIGNUM *rB,
	const unsigned char RB[65],
	const unsigned char RA[65],
	const unsigned char g2[384],
	const char *IDA, size_t IDAlen,
	SMXPrivateKey *skB);

int SMX_MASTER_KEY_print(BIO *bp, const SMX_MASTER_KEY *x, int off);
int SMX_KEY_print(BIO *bp, const SMX_KEY *x, int off);

SMXCiphertext *d2i_SMXCiphertext_bio(BIO *bp, SMXCiphertext **a);
int i2d_SMXMasterSecret_bio(BIO *bp, SMXMasterSecret *a);
SMXMasterSecret *d2i_SMXMasterSecret_bio(BIO *bp, SMXMasterSecret **a);
int i2d_SMXPublicParameters_bio(BIO *bp, SMXPublicParameters *a);
SMXPublicParameters *d2i_SMXPublicParameters_bio(BIO *bp, SMXPublicParameters **a);
int i2d_SMXPrivateKey_bio(BIO *bp, SMXPrivateKey *a);
SMXPrivateKey *d2i_SMXPrivateKey_bio(BIO *bp, SMXPrivateKey **a);
int i2d_SMXSignature_bio(BIO *bp, SMXSignature *a);
SMXSignature *d2i_SMXSignature_bio(BIO *bp, SMXSignature **a);
int i2d_SMXCiphertext_bio(BIO *bp, SMXCiphertext *a);

#ifndef OPENSSL_NO_STDIO
SMXMasterSecret *d2i_SMXMasterSecret_fp(FILE *fp, SMXMasterSecret **pp);
SMXPublicParameters *d2i_SMXPublicParameters_fp(FILE *fp, SMXPublicParameters **pp);
SMXPrivateKey *d2i_SMXPrivateKey_fp(FILE *fp, SMXPrivateKey **pp);
SMXSignature *d2i_SMXSignature_fp(FILE *fp, SMXSignature **pp);
SMXCiphertext *d2i_SMXCiphertext_fp(FILE *fp, SMXCiphertext **pp);

int i2d_SMXMasterSecret_fp(FILE *fp, SMXMasterSecret *a);
int i2d_SMXPublicParameters_fp(FILE *fp, SMXPublicParameters *a);
int i2d_SMXPrivateKey_fp(FILE *fp, SMXPrivateKey *a);
int i2d_SMXSignature_fp(FILE *fp, SMXSignature *a);
int i2d_SMXCiphertext_fp(FILE *fp, SMXCiphertext *a);
#endif

DECLARE_ASN1_ENCODE_FUNCTIONS_const(SMX_MASTER_KEY,SMXMasterSecret)
DECLARE_ASN1_ENCODE_FUNCTIONS_const(SMX_MASTER_KEY,SMXPublicParameters)
DECLARE_ASN1_ENCODE_FUNCTIONS_const(SMX_KEY,SMXPrivateKey)
DECLARE_ASN1_ENCODE_FUNCTIONS_const(SMX_KEY,SMXPublicKey)
DECLARE_ASN1_FUNCTIONS(SMXSignature)
DECLARE_ASN1_FUNCTIONS(SMXCiphertext)

#define SMXMasterSecret_new() SMX_MASTER_KEY_new()
#define SMXMasterSecret_free(a) SMX_MASTER_KEY_free(a)
#define SMXPublicParameters_new() SMX_MASTER_KEY_new()
#define SMXPublicParameters_free(a) SMX_MASTER_KEY_free(a)
#define SMXPrivateKey_new() SMX_KEY_new()
#define SMXPrivateKey_free(a) SMX_KEY_free(a)
#define SMXPublicKey_new() SMX_KEY_new()
#define SMXPublicKey_free(a) SMX_KEY_free(a)

# define EVP_PKEY_CTRL_SMX_PAIRING		(EVP_PKEY_ALG_CTRL + 1)
# define EVP_PKEY_CTRL_SMX_SCHEME		(EVP_PKEY_ALG_CTRL + 2)
# define EVP_PKEY_CTRL_SMX_HASH1		(EVP_PKEY_ALG_CTRL + 3)
# define EVP_PKEY_CTRL_SMX_SIGN_SCHEME		(EVP_PKEY_ALG_CTRL + 4)
# define EVP_PKEY_CTRL_SMX_ENCRYPT_SCHEME	(EVP_PKEY_ALG_CTRL + 5)
# define EVP_PKEY_CTRL_SMX_ID			(EVP_PKEY_ALG_CTRL + 6)
# define EVP_PKEY_CTRL_GET_SMX_ID		(EVP_PKEY_ALG_CTRL + 7)

# define EVP_PKEY_CTX_set_smx_pairing(ctx, nid) \
	EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_SM9_MASTER, \
		EVP_PKEY_OP_KEYGEN, \
		EVP_PKEY_CTRL_SMX_PAIRING, nid, NULL)

# define EVP_PKEY_CTX_get_smx_pairing(ctx) \
	EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_SM9_MASTER, \
		EVP_PKEY_OP_KEYGEN, \
		EVP_PKEY_CTRL_SMX_PAIRING, -2, NULL)

# define EVP_PKEY_CTX_set_smx_scheme(ctx, nid) \
	EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_SM9_MASTER, \
		EVP_PKEY_OP_KEYGEN, \
		EVP_PKEY_CTRL_SMX_SCHEME, nid, NULL)

# define EVP_PKEY_CTX_get_smx_scheme(ctx) \
	EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_SM9_MASTER, \
		EVP_PKEY_OP_KEYGEN, \
		EVP_PKEY_CTRL_SMX_SCHEME, -2, NULL)

# define EVP_PKEY_CTX_set_smx_hash1(ctx, nid) \
	EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_SM9_MASTER, \
		EVP_PKEY_OP_KEYGEN, EVP_PKEY_CTRL_SMX_HASH1, nid, NULL)

# define EVP_PKEY_CTX_get_smx_hash1(ctx) \
	EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_SM9_MASTER, \
		EVP_PKEY_OP_KEYGEN, EVP_PKEY_CTRL_SMX_HASH1, -2, NULL)

# define EVP_PKEY_CTX_set_smx_encrypt_scheme(ctx, nid) \
	EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_SM9_MASTER, \
		EVP_PKEY_OP_ENCRYPT, \
		EVP_PKEY_CTRL_SMX_ENCRYPT_SCHEME, nid, NULL)

# define EVP_PKEY_CTX_set_smx_decrypt_scheme(ctx, nid) \
	EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_SMX, \
		EVP_PKEY_OP_DECRYPT|EVP_PKEY_OP_ENCRYPT, \
		EVP_PKEY_CTRL_SMX_ENCRYPT_SCHEME, nid, NULL)

# define EVP_PKEY_CTX_set_smx_sign_scheme(ctx, nid) \
	EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_SMX, \
		EVP_PKEY_OP_SIGN|EVP_PKEY_OP_SIGNCTX| \
		EVP_PKEY_OP_VERIFY|EVP_PKEY_OP_VERIFYCTX, \
		EVP_PKEY_CTRL_SMX_SIGN_SCHEME, nid, NULL)

# define EVP_PKEY_CTX_set_smx_verify_scheme(ctx, nid) \
	EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_SM9_MASTER, \
		EVP_PKEY_OP_VERIFY|EVP_PKEY_OP_VERIFYCTX, \
		EVP_PKEY_CTRL_SMX_SIGN_SCHEME, nid, NULL)

# define EVP_PKEY_CTX_set_smx_id(ctx, id) \
	EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_SM9_MASTER, \
		EVP_PKEY_OP_ENCRYPT| \
		EVP_PKEY_OP_VERIFY|EVP_PKEY_OP_VERIFYCTX, \
		EVP_PKEY_CTRL_SMX_ID, 0, (void *)id)

# define EVP_PKEY_CTX_get_smx_id(ctx, pid) \
	EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_SM9_MASTER, \
		EVP_PKEY_OP_ENCRYPT| \
		EVP_PKEY_OP_VERIFY|EVP_PKEY_OP_VERIFYCTX, \
		EVP_PKEY_CTRL_GET_SMX_ID, 0, (void *)pid)

/* BEGIN ERROR CODES */
/*
 * The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */

int ERR_load_SMX_strings(void);

/* Error codes for the SMX functions. */

/* Function codes. */
# define SMX_F_DO_SMX_KEY_PRINT                           100
# define SMX_F_DO_SMX_MASTER_KEY_PRINT                    101
# define SMX_F_PKEY_SMX_COPY                              102
# define SMX_F_PKEY_SMX_CTRL                              103
# define SMX_F_PKEY_SMX_CTRL_STR                          104
# define SMX_F_PKEY_SMX_DECRYPT                           105
# define SMX_F_PKEY_SMX_INIT                              106
# define SMX_F_PKEY_SMX_MASTER_COPY                       107
# define SMX_F_PKEY_SMX_MASTER_CTRL                       108
# define SMX_F_PKEY_SMX_MASTER_CTRL_STR                   109
# define SMX_F_PKEY_SMX_MASTER_ENCRYPT                    110
# define SMX_F_PKEY_SMX_MASTER_INIT                       111
# define SMX_F_PKEY_SMX_MASTER_KEYGEN                     112
# define SMX_F_PKEY_SMX_MASTER_VERIFY                     113
# define SMX_F_PKEY_SMX_SIGN                              114
# define SMX_F_SMX_CIPHERTEXT_SIZE                        141
# define SMX_F_SMX_COMPUTE_SHARE_KEY_A                    115
# define SMX_F_SMX_COMPUTE_SHARE_KEY_B                    116
# define SMX_F_SMX_DECRYPT                                117
# define SMX_F_SMX_ENCRYPT                                118
# define SMX_F_SMX_EXTRACT_PUBLIC_PARAMETERS              119
# define SMX_F_SMX_GENERATE_KEY_EXCHANGE                  120
# define SMX_F_SMX_GENERATE_MASTER_SECRET                 121
# define SMX_F_SMX_KEY_NEW                                122
# define SMX_F_SMX_MASTER_KEY_EXTRACT_KEY                 123
# define SMX_F_SMX_MASTER_KEY_NEW                         124
# define SMX_F_SMX_MASTER_OLD_PRIV_DECODE                 125
# define SMX_F_SMX_MASTER_PRIV_DECODE                     126
# define SMX_F_SMX_MASTER_PRIV_ENCODE                     127
# define SMX_F_SMX_MASTER_PUB_DECODE                      128
# define SMX_F_SMX_OLD_PRIV_DECODE                        129
# define SMX_F_SMX_PRIV_DECODE                            130
# define SMX_F_SMX_PRIV_ENCODE                            131
# define SMX_F_SMX_PUB_DECODE                             132
# define SMX_F_SMX_SIGN                                   133
# define SMX_F_SMX_SIGNFINAL                              134
# define SMX_F_SMX_SIGNINIT                               135
# define SMX_F_SMX_UNWRAP_KEY                             136
# define SMX_F_SMX_VERIFY                                 137
# define SMX_F_SMX_VERIFYFINAL                            138
# define SMX_F_SMX_VERIFYINIT                             139
# define SMX_F_SMX_WRAP_KEY                               140

/* Reason codes. */
# define SMX_R_BUFFER_TOO_SMALL                           100
# define SMX_R_DECODE_ERROR                               101
# define SMX_R_DIGEST_FAILURE                             102
# define SMX_R_EC_LIB                                     103
# define SMX_R_EXTENSION_FIELD_ERROR                      104
# define SMX_R_IDENTITY_REQUIRED                          105
# define SMX_R_INVALID_DIGEST_TYPE                        106
# define SMX_R_INVALID_ENCRYPT_SCHEME                     107
# define SMX_R_INVALID_HASH1                              108
# define SMX_R_INVALID_HASH2_DIGEST                       109
# define SMX_R_INVALID_ID                                 110
# define SMX_R_INVALID_KEM_KEY_LENGTH                     111
# define SMX_R_INVALID_KEY_AGREEMENT_CHECKSUM             112
# define SMX_R_INVALID_KEY_USAGE                          113
# define SMX_R_INVALID_PAIRING                            114
# define SMX_R_INVALID_PAIRING_TYPE                       115
# define SMX_R_INVALID_POINTPPUB                          116
# define SMX_R_INVALID_PRIVATE_POINT                      117
# define SMX_R_INVALID_SCHEME                             118
# define SMX_R_INVALID_SIGNATURE                          119
# define SMX_R_INVALID_SIGNATURE_FORMAT                   120
# define SMX_R_INVALID_SIGN_MD                            121
# define SMX_R_INVALID_SIGN_SCHEME                        122
# define SMX_R_INVALID_SMX_SCHEME                         123
# define SMX_R_NO_MASTER_SECRET                           124
# define SMX_R_PAIRING_ERROR                              125
# define SMX_R_PLAINTEXT_TOO_LONG                         131
# define SMX_R_RATE_PAIRING_ERROR                         126
# define SMX_R_SIGNER_ID_REQUIRED                         127
# define SMX_R_TWIST_CURVE_ERROR                          128
# define SMX_R_VERIFY_FAILURE                             129
# define SMX_R_ZERO_ID                                    130

#  ifdef  __cplusplus
}
#  endif
# endif
#endif
