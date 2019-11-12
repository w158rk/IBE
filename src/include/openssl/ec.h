/*
 * Copyright 2002-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 *
 * Portions of the attached software ("Contribution") are developed by
 * SUN MICROSYSTEMS, INC., and are contributed to the OpenSSL project.
 *
 * The Contribution is licensed pursuant to the OpenSSL open source
 * license provided above.
 *
 * The elliptic curve binary polynomial software is originally written by
 * Sheueling Chang Shantz and Douglas Stebila of Sun Microsystems Laboratories.
 *
 */

#ifndef HEADER_EC_H
# define HEADER_EC_H

# include <openssl/opensslconf.h>

# ifndef OPENSSL_NO_EC
# include <openssl/asn1.h>
# include <openssl/symhacks.h>
# if OPENSSL_API_COMPAT < 0x10100000L
#  include <openssl/bn.h>
# endif
# ifdef  __cplusplus
extern "C" {
# endif

# ifndef OPENSSL_ECC_MAX_FIELD_BITS
#  define OPENSSL_ECC_MAX_FIELD_BITS 661
# endif

/** Enum for the point conversion form as defined in X9.62 (ECDSA)
 *  for the encoding of a elliptic curve point (x,y) */
typedef enum {
        /** the point is encoded as z||x, where the octet z specifies
         *  which solution of the quadratic equation y is  */
    POINT_CONVERSION_COMPRESSED = 2,
        /** the point is encoded as z||x||y, where z is the octet 0x04  */
    POINT_CONVERSION_UNCOMPRESSED = 4,
        /** the point is encoded as z||x||y, where the octet z specifies
         *  which solution of the quadratic equation y is  */
    POINT_CONVERSION_HYBRID = 6
} point_conversion_form_t;

typedef struct ec_method_st EC_METHOD;
typedef struct ec_group_st EC_GROUP;
typedef struct ec_point_st EC_POINT;
typedef struct ecpk_parameters_st ECPKPARAMETERS;
typedef struct ec_parameters_st ECPARAMETERS;

/********************************************************************/
/*               EC_METHODs for curves over GF(p)                   */
/********************************************************************/

/** Returns the basic GFp ec methods which provides the basis for the
 *  optimized methods.
 *  \return  EC_METHOD object
 */
const EC_METHOD *EC_GFp_simple_method(void);

/** Returns GFp methods using montgomery multiplication.
 *  \return  EC_METHOD object
 */
const EC_METHOD *EC_GFp_mont_method(void);

/** Returns GFp methods using optimized methods for NIST recommended curves
 *  \return  EC_METHOD object
 */
const EC_METHOD *EC_GFp_nist_method(void);

# ifndef OPENSSL_NO_EC_NISTP_64_GCC_128
/** Returns 64-bit optimized methods for nistp224
 *  \return  EC_METHOD object
 */
const EC_METHOD *EC_GFp_nistp224_method(void);

/** Returns 64-bit optimized methods for nistp256
 *  \return  EC_METHOD object
 */
const EC_METHOD *EC_GFp_nistp256_method(void);

/** Returns 64-bit optimized methods for nistp521
 *  \return  EC_METHOD object
 */
const EC_METHOD *EC_GFp_nistp521_method(void);

#  ifndef OPENSSL_NO_SM2
const EC_METHOD *EC_GFp_sm2p256_method(void);
#  endif
# endif

# ifndef OPENSSL_NO_EC2M
/********************************************************************/
/*           EC_METHOD for curves over GF(2^m)                      */
/********************************************************************/

/** Returns the basic GF2m ec method
 *  \return  EC_METHOD object
 */
const EC_METHOD *EC_GF2m_simple_method(void);

# endif

/********************************************************************/
/*                   EC_GROUP functions                             */
/********************************************************************/

/** Creates a new EC_GROUP object
 *  \param   meth  EC_METHOD to use
 *  \return  newly created EC_GROUP object or NULL in case of an error.
 */
EC_GROUP *EC_GROUP_new(const EC_METHOD *meth);

/** Frees a EC_GROUP object
 *  \param  group  EC_GROUP object to be freed.
 */
void EC_GROUP_free(EC_GROUP *group);

/** Clears and frees a EC_GROUP object
 *  \param  group  EC_GROUP object to be cleared and freed.
 */
void EC_GROUP_clear_free(EC_GROUP *group);

/** Copies EC_GROUP objects. Note: both EC_GROUPs must use the same EC_METHOD.
 *  \param  dst  destination EC_GROUP object
 *  \param  src  source EC_GROUP object
 *  \return 1 on success and 0 if an error occurred.
 */
int EC_GROUP_copy(EC_GROUP *dst, const EC_GROUP *src);

/** Creates a new EC_GROUP object and copies the copies the content
 *  form src to the newly created EC_KEY object
 *  \param  src  source EC_GROUP object
 *  \return newly created EC_GROUP object or NULL in case of an error.
 */
EC_GROUP *EC_GROUP_dup(const EC_GROUP *src);

/** Returns the EC_METHOD of the EC_GROUP object.
 *  \param  group  EC_GROUP object
 *  \return EC_METHOD used in this EC_GROUP object.
 */
const EC_METHOD *EC_GROUP_method_of(const EC_GROUP *group);

/** Returns the field type of the EC_METHOD.
 *  \param  meth  EC_METHOD object
 *  \return NID of the underlying field type OID.
 */
int EC_METHOD_get_field_type(const EC_METHOD *meth);

/** Sets the generator and it's order/cofactor of a EC_GROUP object.
 *  \param  group      EC_GROUP object
 *  \param  generator  EC_POINT object with the generator.
 *  \param  order      the order of the group generated by the generator.
 *  \param  cofactor   the index of the sub-group generated by the generator
 *                     in the group of all points on the elliptic curve.
 *  \return 1 on success and 0 if an error occurred
 */
int EC_GROUP_set_generator(EC_GROUP *group, const EC_POINT *generator,
                           const BIGNUM *order, const BIGNUM *cofactor);

/** Returns the generator of a EC_GROUP object.
 *  \param  group  EC_GROUP object
 *  \return the currently used generator (possibly NULL).
 */
const EC_POINT *EC_GROUP_get0_generator(const EC_GROUP *group);

/** Returns the montgomery data for order(Generator)
 *  \param  group  EC_GROUP object
 *  \return the currently used montgomery data (possibly NULL).
*/
BN_MONT_CTX *EC_GROUP_get_mont_data(const EC_GROUP *group);

/** Gets the order of a EC_GROUP
 *  \param  group  EC_GROUP object
 *  \param  order  BIGNUM to which the order is copied
 *  \param  ctx    unused
 *  \return 1 on success and 0 if an error occurred
 */
int EC_GROUP_get_order(const EC_GROUP *group, BIGNUM *order, BN_CTX *ctx);

/** Gets the order of an EC_GROUP
 *  \param  group  EC_GROUP object
 *  \return the group order
 */
const BIGNUM *EC_GROUP_get0_order(const EC_GROUP *group);

/** Gets the number of bits of the order of an EC_GROUP
 *  \param  group  EC_GROUP object
 *  \return number of bits of group order.
 */
int EC_GROUP_order_bits(const EC_GROUP *group);

/** Gets the cofactor of a EC_GROUP
 *  \param  group     EC_GROUP object
 *  \param  cofactor  BIGNUM to which the cofactor is copied
 *  \param  ctx       unused
 *  \return 1 on success and 0 if an error occurred
 */
int EC_GROUP_get_cofactor(const EC_GROUP *group, BIGNUM *cofactor,
                          BN_CTX *ctx);

/** Gets the cofactor of an EC_GROUP
 *  \param  group  EC_GROUP object
 *  \return the group cofactor
 */
const BIGNUM *EC_GROUP_get0_cofactor(const EC_GROUP *group);

/** Sets the name of a EC_GROUP object
 *  \param  group  EC_GROUP object
 *  \param  nid    NID of the curve name OID
 */
void EC_GROUP_set_curve_name(EC_GROUP *group, int nid);

/** Returns the curve name of a EC_GROUP object
 *  \param  group  EC_GROUP object
 *  \return NID of the curve name OID or 0 if not set.
 */
int EC_GROUP_get_curve_name(const EC_GROUP *group);

void EC_GROUP_set_asn1_flag(EC_GROUP *group, int flag);
int EC_GROUP_get_asn1_flag(const EC_GROUP *group);

void EC_GROUP_set_point_conversion_form(EC_GROUP *group,
                                        point_conversion_form_t form);
point_conversion_form_t EC_GROUP_get_point_conversion_form(const EC_GROUP *);

unsigned char *EC_GROUP_get0_seed(const EC_GROUP *x);
size_t EC_GROUP_get_seed_len(const EC_GROUP *);
size_t EC_GROUP_set_seed(EC_GROUP *, const unsigned char *, size_t len);

/** Sets the parameter of a ec over GFp defined by y^2 = x^3 + a*x + b
 *  \param  group  EC_GROUP object
 *  \param  p      BIGNUM with the prime number
 *  \param  a      BIGNUM with parameter a of the equation
 *  \param  b      BIGNUM with parameter b of the equation
 *  \param  ctx    BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
int EC_GROUP_set_curve_GFp(EC_GROUP *group, const BIGNUM *p, const BIGNUM *a,
                           const BIGNUM *b, BN_CTX *ctx);

/** Gets the parameter of the ec over GFp defined by y^2 = x^3 + a*x + b
 *  \param  group  EC_GROUP object
 *  \param  p      BIGNUM for the prime number
 *  \param  a      BIGNUM for parameter a of the equation
 *  \param  b      BIGNUM for parameter b of the equation
 *  \param  ctx    BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
int EC_GROUP_get_curve_GFp(const EC_GROUP *group, BIGNUM *p, BIGNUM *a,
                           BIGNUM *b, BN_CTX *ctx);

# ifndef OPENSSL_NO_EC2M
/** Sets the parameter of a ec over GF2m defined by y^2 + x*y = x^3 + a*x^2 + b
 *  \param  group  EC_GROUP object
 *  \param  p      BIGNUM with the polynomial defining the underlying field
 *  \param  a      BIGNUM with parameter a of the equation
 *  \param  b      BIGNUM with parameter b of the equation
 *  \param  ctx    BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
int EC_GROUP_set_curve_GF2m(EC_GROUP *group, const BIGNUM *p, const BIGNUM *a,
                            const BIGNUM *b, BN_CTX *ctx);

/** Gets the parameter of the ec over GF2m defined by y^2 + x*y = x^3 + a*x^2 + b
 *  \param  group  EC_GROUP object
 *  \param  p      BIGNUM for the polynomial defining the underlying field
 *  \param  a      BIGNUM for parameter a of the equation
 *  \param  b      BIGNUM for parameter b of the equation
 *  \param  ctx    BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
int EC_GROUP_get_curve_GF2m(const EC_GROUP *group, BIGNUM *p, BIGNUM *a,
                            BIGNUM *b, BN_CTX *ctx);
# endif
/** Returns the number of bits needed to represent a field element
 *  \param  group  EC_GROUP object
 *  \return number of bits needed to represent a field element
 */
int EC_GROUP_get_degree(const EC_GROUP *group);

/** Checks whether the parameter in the EC_GROUP define a valid ec group
 *  \param  group  EC_GROUP object
 *  \param  ctx    BN_CTX object (optional)
 *  \return 1 if group is a valid ec group and 0 otherwise
 */
int EC_GROUP_check(const EC_GROUP *group, BN_CTX *ctx);

/** Checks whether the discriminant of the elliptic curve is zero or not
 *  \param  group  EC_GROUP object
 *  \param  ctx    BN_CTX object (optional)
 *  \return 1 if the discriminant is not zero and 0 otherwise
 */
int EC_GROUP_check_discriminant(const EC_GROUP *group, BN_CTX *ctx);

/** Compares two EC_GROUP objects
 *  \param  a    first EC_GROUP object
 *  \param  b    second EC_GROUP object
 *  \param  ctx  BN_CTX object (optional)
 *  \return 0 if the groups are equal, 1 if not, or -1 on error
 */
int EC_GROUP_cmp(const EC_GROUP *a, const EC_GROUP *b, BN_CTX *ctx);

/*
 * EC_GROUP_new_GF*() calls EC_GROUP_new() and EC_GROUP_set_GF*() after
 * choosing an appropriate EC_METHOD
 */

/** Creates a new EC_GROUP object with the specified parameters defined
 *  over GFp (defined by the equation y^2 = x^3 + a*x + b)
 *  \param  p    BIGNUM with the prime number
 *  \param  a    BIGNUM with the parameter a of the equation
 *  \param  b    BIGNUM with the parameter b of the equation
 *  \param  ctx  BN_CTX object (optional)
 *  \return newly created EC_GROUP object with the specified parameters
 */
EC_GROUP *EC_GROUP_new_curve_GFp(const BIGNUM *p, const BIGNUM *a,
                                 const BIGNUM *b, BN_CTX *ctx);
# ifndef OPENSSL_NO_EC2M
/** Creates a new EC_GROUP object with the specified parameters defined
 *  over GF2m (defined by the equation y^2 + x*y = x^3 + a*x^2 + b)
 *  \param  p    BIGNUM with the polynomial defining the underlying field
 *  \param  a    BIGNUM with the parameter a of the equation
 *  \param  b    BIGNUM with the parameter b of the equation
 *  \param  ctx  BN_CTX object (optional)
 *  \return newly created EC_GROUP object with the specified parameters
 */
EC_GROUP *EC_GROUP_new_curve_GF2m(const BIGNUM *p, const BIGNUM *a,
                                  const BIGNUM *b, BN_CTX *ctx);
# endif

/** Creates a EC_GROUP object with a curve specified by a NID
 *  \param  nid  NID of the OID of the curve name
 *  \return newly created EC_GROUP object with specified curve or NULL
 *          if an error occurred
 */
EC_GROUP *EC_GROUP_new_by_curve_name(int nid);

/** Creates a new EC_GROUP object from an ECPARAMETERS object
 *  \param  params  pointer to the ECPARAMETERS object
 *  \return newly created EC_GROUP object with specified curve or NULL
 *          if an error occurred
 */
EC_GROUP *EC_GROUP_new_from_ecparameters(const ECPARAMETERS *params);

/** Creates an ECPARAMETERS object for the the given EC_GROUP object.
 *  \param  group   pointer to the EC_GROUP object
 *  \param  params  pointer to an existing ECPARAMETERS object or NULL
 *  \return pointer to the new ECPARAMETERS object or NULL
 *          if an error occurred.
 */
ECPARAMETERS *EC_GROUP_get_ecparameters(const EC_GROUP *group,
                                        ECPARAMETERS *params);

/** Creates a new EC_GROUP object from an ECPKPARAMETERS object
 *  \param  params  pointer to an existing ECPKPARAMETERS object, or NULL
 *  \return newly created EC_GROUP object with specified curve, or NULL
 *          if an error occurred
 */
EC_GROUP *EC_GROUP_new_from_ecpkparameters(const ECPKPARAMETERS *params);

/** Creates an ECPKPARAMETERS object for the the given EC_GROUP object.
 *  \param  group   pointer to the EC_GROUP object
 *  \param  params  pointer to an existing ECPKPARAMETERS object or NULL
 *  \return pointer to the new ECPKPARAMETERS object or NULL
 *          if an error occurred.
 */
ECPKPARAMETERS *EC_GROUP_get_ecpkparameters(const EC_GROUP *group,
                                            ECPKPARAMETERS *params);

/********************************************************************/
/*               handling of internal curves                        */
/********************************************************************/

typedef struct {
    int nid;
    const char *comment;
} EC_builtin_curve;

/*
 * EC_builtin_curves(EC_builtin_curve *r, size_t size) returns number of all
 * available curves or zero if a error occurred. In case r is not zero,
 * nitems EC_builtin_curve structures are filled with the data of the first
 * nitems internal groups
 */
size_t EC_get_builtin_curves(EC_builtin_curve *r, size_t nitems);

const char *EC_curve_nid2nist(int nid);
int EC_curve_nist2nid(const char *name);

/********************************************************************/
/*                    EC_POINT functions                            */
/********************************************************************/

/** Creates a new EC_POINT object for the specified EC_GROUP
 *  \param  group  EC_GROUP the underlying EC_GROUP object
 *  \return newly created EC_POINT object or NULL if an error occurred
 */
EC_POINT *EC_POINT_new(const EC_GROUP *group);

/** Frees a EC_POINT object
 *  \param  point  EC_POINT object to be freed
 */
void EC_POINT_free(EC_POINT *point);

/** Clears and frees a EC_POINT object
 *  \param  point  EC_POINT object to be cleared and freed
 */
void EC_POINT_clear_free(EC_POINT *point);

/** Copies EC_POINT object
 *  \param  dst  destination EC_POINT object
 *  \param  src  source EC_POINT object
 *  \return 1 on success and 0 if an error occurred
 */
int EC_POINT_copy(EC_POINT *dst, const EC_POINT *src);

/** Creates a new EC_POINT object and copies the content of the supplied
 *  EC_POINT
 *  \param  src    source EC_POINT object
 *  \param  group  underlying the EC_GROUP object
 *  \return newly created EC_POINT object or NULL if an error occurred
 */
EC_POINT *EC_POINT_dup(const EC_POINT *src, const EC_GROUP *group);

/** Returns the EC_METHOD used in EC_POINT object
 *  \param  point  EC_POINT object
 *  \return the EC_METHOD used
 */
const EC_METHOD *EC_POINT_method_of(const EC_POINT *point);

/** Sets a point to infinity (neutral element)
 *  \param  group  underlying EC_GROUP object
 *  \param  point  EC_POINT to set to infinity
 *  \return 1 on success and 0 if an error occurred
 */
int EC_POINT_set_to_infinity(const EC_GROUP *group, EC_POINT *point);

/** Sets the jacobian projective coordinates of a EC_POINT over GFp
 *  \param  group  underlying EC_GROUP object
 *  \param  p      EC_POINT object
 *  \param  x      BIGNUM with the x-coordinate
 *  \param  y      BIGNUM with the y-coordinate
 *  \param  z      BIGNUM with the z-coordinate
 *  \param  ctx    BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
int EC_POINT_set_Jprojective_coordinates_GFp(const EC_GROUP *group,
                                             EC_POINT *p, const BIGNUM *x,
                                             const BIGNUM *y, const BIGNUM *z,
                                             BN_CTX *ctx);

/** Gets the jacobian projective coordinates of a EC_POINT over GFp
 *  \param  group  underlying EC_GROUP object
 *  \param  p      EC_POINT object
 *  \param  x      BIGNUM for the x-coordinate
 *  \param  y      BIGNUM for the y-coordinate
 *  \param  z      BIGNUM for the z-coordinate
 *  \param  ctx    BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
int EC_POINT_get_Jprojective_coordinates_GFp(const EC_GROUP *group,
                                             const EC_POINT *p, BIGNUM *x,
                                             BIGNUM *y, BIGNUM *z,
                                             BN_CTX *ctx);

/** Sets the affine coordinates of a EC_POINT over GFp
 *  \param  group  underlying EC_GROUP object
 *  \param  p      EC_POINT object
 *  \param  x      BIGNUM with the x-coordinate
 *  \param  y      BIGNUM with the y-coordinate
 *  \param  ctx    BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
int EC_POINT_set_affine_coordinates_GFp(const EC_GROUP *group, EC_POINT *p,
                                        const BIGNUM *x, const BIGNUM *y,
                                        BN_CTX *ctx);

/** Gets the affine coordinates of a EC_POINT over GFp
 *  \param  group  underlying EC_GROUP object
 *  \param  p      EC_POINT object
 *  \param  x      BIGNUM for the x-coordinate
 *  \param  y      BIGNUM for the y-coordinate
 *  \param  ctx    BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
int EC_POINT_get_affine_coordinates_GFp(const EC_GROUP *group,
                                        const EC_POINT *p, BIGNUM *x,
                                        BIGNUM *y, BN_CTX *ctx);

/** Sets the x9.62 compressed coordinates of a EC_POINT over GFp
 *  \param  group  underlying EC_GROUP object
 *  \param  p      EC_POINT object
 *  \param  x      BIGNUM with x-coordinate
 *  \param  y_bit  integer with the y-Bit (either 0 or 1)
 *  \param  ctx    BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
int EC_POINT_set_compressed_coordinates_GFp(const EC_GROUP *group,
                                            EC_POINT *p, const BIGNUM *x,
                                            int y_bit, BN_CTX *ctx);
# ifndef OPENSSL_NO_EC2M
/** Sets the affine coordinates of a EC_POINT over GF2m
 *  \param  group  underlying EC_GROUP object
 *  \param  p      EC_POINT object
 *  \param  x      BIGNUM with the x-coordinate
 *  \param  y      BIGNUM with the y-coordinate
 *  \param  ctx    BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
int EC_POINT_set_affine_coordinates_GF2m(const EC_GROUP *group, EC_POINT *p,
                                         const BIGNUM *x, const BIGNUM *y,
                                         BN_CTX *ctx);

/** Gets the affine coordinates of a EC_POINT over GF2m
 *  \param  group  underlying EC_GROUP object
 *  \param  p      EC_POINT object
 *  \param  x      BIGNUM for the x-coordinate
 *  \param  y      BIGNUM for the y-coordinate
 *  \param  ctx    BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
int EC_POINT_get_affine_coordinates_GF2m(const EC_GROUP *group,
                                         const EC_POINT *p, BIGNUM *x,
                                         BIGNUM *y, BN_CTX *ctx);

/** Sets the x9.62 compressed coordinates of a EC_POINT over GF2m
 *  \param  group  underlying EC_GROUP object
 *  \param  p      EC_POINT object
 *  \param  x      BIGNUM with x-coordinate
 *  \param  y_bit  integer with the y-Bit (either 0 or 1)
 *  \param  ctx    BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
int EC_POINT_set_compressed_coordinates_GF2m(const EC_GROUP *group,
                                             EC_POINT *p, const BIGNUM *x,
                                             int y_bit, BN_CTX *ctx);
# endif
/** Encodes a EC_POINT object to a octet string
 *  \param  group  underlying EC_GROUP object
 *  \param  p      EC_POINT object
 *  \param  form   point conversion form
 *  \param  buf    memory buffer for the result. If NULL the function returns
 *                 required buffer size.
 *  \param  len    length of the memory buffer
 *  \param  ctx    BN_CTX object (optional)
 *  \return the length of the encoded octet string or 0 if an error occurred
 */
size_t EC_POINT_point2oct(const EC_GROUP *group, const EC_POINT *p,
                          point_conversion_form_t form,
                          unsigned char *buf, size_t len, BN_CTX *ctx);

/** Decodes a EC_POINT from a octet string
 *  \param  group  underlying EC_GROUP object
 *  \param  p      EC_POINT object
 *  \param  buf    memory buffer with the encoded ec point
 *  \param  len    length of the encoded ec point
 *  \param  ctx    BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
int EC_POINT_oct2point(const EC_GROUP *group, EC_POINT *p,
                       const unsigned char *buf, size_t len, BN_CTX *ctx);

/** Encodes an EC_POINT object to an allocated octet string
 *  \param  group  underlying EC_GROUP object
 *  \param  point  EC_POINT object
 *  \param  form   point conversion form
 *  \param  pbuf   returns pointer to allocated buffer
 *  \param  len    length of the memory buffer
 *  \param  ctx    BN_CTX object (optional)
 *  \return the length of the encoded octet string or 0 if an error occurred
 */

size_t EC_POINT_point2buf(const EC_GROUP *group, const EC_POINT *point,
                          point_conversion_form_t form,
                          unsigned char **pbuf, BN_CTX *ctx);

/* other interfaces to point2oct/oct2point: */
BIGNUM *EC_POINT_point2bn(const EC_GROUP *, const EC_POINT *,
                          point_conversion_form_t form, BIGNUM *, BN_CTX *);
EC_POINT *EC_POINT_bn2point(const EC_GROUP *, const BIGNUM *,
                            EC_POINT *, BN_CTX *);
char *EC_POINT_point2hex(const EC_GROUP *, const EC_POINT *,
                         point_conversion_form_t form, BN_CTX *);
EC_POINT *EC_POINT_hex2point(const EC_GROUP *, const char *,
                             EC_POINT *, BN_CTX *);

/********************************************************************/
/*         functions for doing EC_POINT arithmetic                  */
/********************************************************************/

/** Computes the sum of two EC_POINT
 *  \param  group  underlying EC_GROUP object
 *  \param  r      EC_POINT object for the result (r = a + b)
 *  \param  a      EC_POINT object with the first summand
 *  \param  b      EC_POINT object with the second summand
 *  \param  ctx    BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
int EC_POINT_add(const EC_GROUP *group, EC_POINT *r, const EC_POINT *a,
                 const EC_POINT *b, BN_CTX *ctx);

/** Computes the double of a EC_POINT
 *  \param  group  underlying EC_GROUP object
 *  \param  r      EC_POINT object for the result (r = 2 * a)
 *  \param  a      EC_POINT object
 *  \param  ctx    BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
int EC_POINT_dbl(const EC_GROUP *group, EC_POINT *r, const EC_POINT *a,
                 BN_CTX *ctx);

/** Computes the inverse of a EC_POINT
 *  \param  group  underlying EC_GROUP object
 *  \param  a      EC_POINT object to be inverted (it's used for the result as well)
 *  \param  ctx    BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
int EC_POINT_invert(const EC_GROUP *group, EC_POINT *a, BN_CTX *ctx);

/** Checks whether the point is the neutral element of the group
 *  \param  group  the underlying EC_GROUP object
 *  \param  p      EC_POINT object
 *  \return 1 if the point is the neutral element and 0 otherwise
 */
int EC_POINT_is_at_infinity(const EC_GROUP *group, const EC_POINT *p);

/** Checks whether the point is on the curve
 *  \param  group  underlying EC_GROUP object
 *  \param  point  EC_POINT object to check
 *  \param  ctx    BN_CTX object (optional)
 *  \return 1 if the point is on the curve, 0 if not, or -1 on error
 */
int EC_POINT_is_on_curve(const EC_GROUP *group, const EC_POINT *point,
                         BN_CTX *ctx);

/** Compares two EC_POINTs
 *  \param  group  underlying EC_GROUP object
 *  \param  a      first EC_POINT object
 *  \param  b      second EC_POINT object
 *  \param  ctx    BN_CTX object (optional)
 *  \return 1 if the points are not equal, 0 if they are, or -1 on error
 */
int EC_POINT_cmp(const EC_GROUP *group, const EC_POINT *a, const EC_POINT *b,
                 BN_CTX *ctx);

int EC_POINT_make_affine(const EC_GROUP *group, EC_POINT *point, BN_CTX *ctx);
int EC_POINTs_make_affine(const EC_GROUP *group, size_t num,
                          EC_POINT *points[], BN_CTX *ctx);

/** Computes r = generator * n + sum_{i=0}^{num-1} p[i] * m[i]
 *  \param  group  underlying EC_GROUP object
 *  \param  r      EC_POINT object for the result
 *  \param  n      BIGNUM with the multiplier for the group generator (optional)
 *  \param  num    number further summands
 *  \param  p      array of size num of EC_POINT objects
 *  \param  m      array of size num of BIGNUM objects
 *  \param  ctx    BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
int EC_POINTs_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *n,
                  size_t num, const EC_POINT *p[], const BIGNUM *m[],
                  BN_CTX *ctx);

/** Computes r = generator * n + q * m
 *  \param  group  underlying EC_GROUP object
 *  \param  r      EC_POINT object for the result
 *  \param  n      BIGNUM with the multiplier for the group generator (optional)
 *  \param  q      EC_POINT object with the first factor of the second summand
 *  \param  m      BIGNUM with the second factor of the second summand
 *  \param  ctx    BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
int EC_POINT_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *n,
                 const EC_POINT *q, const BIGNUM *m, BN_CTX *ctx);

/** Stores multiples of generator for faster point multiplication
 *  \param  group  EC_GROUP object
 *  \param  ctx    BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
int EC_GROUP_precompute_mult(EC_GROUP *group, BN_CTX *ctx);

/** Reports whether a precomputation has been done
 *  \param  group  EC_GROUP object
 *  \return 1 if a pre-computation has been done and 0 otherwise
 */
int EC_GROUP_have_precompute_mult(const EC_GROUP *group);

/********************************************************************/
/*                       ASN1 stuff                                 */
/********************************************************************/

DECLARE_ASN1_ITEM(ECPKPARAMETERS)
DECLARE_ASN1_ALLOC_FUNCTIONS(ECPKPARAMETERS)
DECLARE_ASN1_ITEM(ECPARAMETERS)
DECLARE_ASN1_ALLOC_FUNCTIONS(ECPARAMETERS)

/*
 * EC_GROUP_get_basis_type() returns the NID of the basis type used to
 * represent the field elements
 */
int EC_GROUP_get_basis_type(const EC_GROUP *);
# ifndef OPENSSL_NO_EC2M
int EC_GROUP_get_trinomial_basis(const EC_GROUP *, unsigned int *k);
int EC_GROUP_get_pentanomial_basis(const EC_GROUP *, unsigned int *k1,
                                   unsigned int *k2, unsigned int *k3);
# endif

# define OPENSSL_EC_EXPLICIT_CURVE  0x000
# define OPENSSL_EC_NAMED_CURVE     0x001

EC_GROUP *d2i_ECPKParameters(EC_GROUP **, const unsigned char **in, long len);
int i2d_ECPKParameters(const EC_GROUP *, unsigned char **out);

# define d2i_ECPKParameters_bio(bp,x) ASN1_d2i_bio_of(EC_GROUP,NULL,d2i_ECPKParameters,bp,x)
# define i2d_ECPKParameters_bio(bp,x) ASN1_i2d_bio_of_const(EC_GROUP,i2d_ECPKParameters,bp,x)
# define d2i_ECPKParameters_fp(fp,x) (EC_GROUP *)ASN1_d2i_fp(NULL, \
                (char *(*)())d2i_ECPKParameters,(fp),(unsigned char **)(x))
# define i2d_ECPKParameters_fp(fp,x) ASN1_i2d_fp(i2d_ECPKParameters,(fp), \
                (unsigned char *)(x))

int ECPKParameters_print(BIO *bp, const EC_GROUP *x, int off);
# ifndef OPENSSL_NO_STDIO
int ECPKParameters_print_fp(FILE *fp, const EC_GROUP *x, int off);
# endif

/********************************************************************/
/*                      EC_KEY functions                            */
/********************************************************************/

/* some values for the encoding_flag */
# define EC_PKEY_NO_PARAMETERS   0x001
# define EC_PKEY_NO_PUBKEY       0x002

/* some values for the flags field */
# define EC_FLAG_NON_FIPS_ALLOW  0x1
# define EC_FLAG_FIPS_CHECKED    0x2
# define EC_FLAG_COFACTOR_ECDH   0x1000

/** Creates a new EC_KEY object.
 *  \return EC_KEY object or NULL if an error occurred.
 */
EC_KEY *EC_KEY_new(void);

int EC_KEY_get_flags(const EC_KEY *key);

void EC_KEY_set_flags(EC_KEY *key, int flags);

void EC_KEY_clear_flags(EC_KEY *key, int flags);

/** Creates a new EC_KEY object using a named curve as underlying
 *  EC_GROUP object.
 *  \param  nid  NID of the named curve.
 *  \return EC_KEY object or NULL if an error occurred.
 */
EC_KEY *EC_KEY_new_by_curve_name(int nid);

/** Frees a EC_KEY object.
 *  \param  key  EC_KEY object to be freed.
 */
void EC_KEY_free(EC_KEY *key);

/** Copies a EC_KEY object.
 *  \param  dst  destination EC_KEY object
 *  \param  src  src EC_KEY object
 *  \return dst or NULL if an error occurred.
 */
EC_KEY *EC_KEY_copy(EC_KEY *dst, const EC_KEY *src);

/** Creates a new EC_KEY object and copies the content from src to it.
 *  \param  src  the source EC_KEY object
 *  \return newly created EC_KEY object or NULL if an error occurred.
 */
EC_KEY *EC_KEY_dup(const EC_KEY *src);

/** Increases the internal reference count of a EC_KEY object.
 *  \param  key  EC_KEY object
 *  \return 1 on success and 0 if an error occurred.
 */
int EC_KEY_up_ref(EC_KEY *key);

/** Returns the EC_GROUP object of a EC_KEY object
 *  \param  key  EC_KEY object
 *  \return the EC_GROUP object (possibly NULL).
 */
const EC_GROUP *EC_KEY_get0_group(const EC_KEY *key);

/** Sets the EC_GROUP of a EC_KEY object.
 *  \param  key    EC_KEY object
 *  \param  group  EC_GROUP to use in the EC_KEY object (note: the EC_KEY
 *                 object will use an own copy of the EC_GROUP).
 *  \return 1 on success and 0 if an error occurred.
 */
int EC_KEY_set_group(EC_KEY *key, const EC_GROUP *group);

/** Returns the private key of a EC_KEY object.
 *  \param  key  EC_KEY object
 *  \return a BIGNUM with the private key (possibly NULL).
 */
const BIGNUM *EC_KEY_get0_private_key(const EC_KEY *key);

/** Sets the private key of a EC_KEY object.
 *  \param  key  EC_KEY object
 *  \param  prv  BIGNUM with the private key (note: the EC_KEY object
 *               will use an own copy of the BIGNUM).
 *  \return 1 on success and 0 if an error occurred.
 */
int EC_KEY_set_private_key(EC_KEY *key, const BIGNUM *prv);

/** Returns the public key of a EC_KEY object.
 *  \param  key  the EC_KEY object
 *  \return a EC_POINT object with the public key (possibly NULL)
 */
const EC_POINT *EC_KEY_get0_public_key(const EC_KEY *key);

/** Sets the public key of a EC_KEY object.
 *  \param  key  EC_KEY object
 *  \param  pub  EC_POINT object with the public key (note: the EC_KEY object
 *               will use an own copy of the EC_POINT object).
 *  \return 1 on success and 0 if an error occurred.
 */
int EC_KEY_set_public_key(EC_KEY *key, const EC_POINT *pub);

unsigned EC_KEY_get_enc_flags(const EC_KEY *key);
void EC_KEY_set_enc_flags(EC_KEY *eckey, unsigned int flags);
point_conversion_form_t EC_KEY_get_conv_form(const EC_KEY *key);
void EC_KEY_set_conv_form(EC_KEY *eckey, point_conversion_form_t cform);

#define EC_KEY_get_ex_new_index(l, p, newf, dupf, freef) \
    CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_EC_KEY, l, p, newf, dupf, freef)
int EC_KEY_set_ex_data(EC_KEY *key, int idx, void *arg);
void *EC_KEY_get_ex_data(const EC_KEY *key, int idx);

/* wrapper functions for the underlying EC_GROUP object */
void EC_KEY_set_asn1_flag(EC_KEY *eckey, int asn1_flag);

/** Creates a table of pre-computed multiples of the generator to
 *  accelerate further EC_KEY operations.
 *  \param  key  EC_KEY object
 *  \param  ctx  BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred.
 */
int EC_KEY_precompute_mult(EC_KEY *key, BN_CTX *ctx);

/** Creates a new ec private (and optional a new public) key.
 *  \param  key  EC_KEY object
 *  \return 1 on success and 0 if an error occurred.
 */
int EC_KEY_generate_key(EC_KEY *key);

/** Verifies that a private and/or public key is valid.
 *  \param  key  the EC_KEY object
 *  \return 1 on success and 0 otherwise.
 */
int EC_KEY_check_key(const EC_KEY *key);

/** Indicates if an EC_KEY can be used for signing.
 *  \param  key  the EC_KEY object
 *  \return 1 if can can sign and 0 otherwise.
 */
int EC_KEY_can_sign(const EC_KEY *eckey);

/** Sets a public key from affine coordinates performing
 *  necessary NIST PKV tests.
 *  \param  key  the EC_KEY object
 *  \param  x    public key x coordinate
 *  \param  y    public key y coordinate
 *  \return 1 on success and 0 otherwise.
 */
int EC_KEY_set_public_key_affine_coordinates(EC_KEY *key, BIGNUM *x,
                                             BIGNUM *y);

/** Encodes an EC_KEY public key to an allocated octet string
 *  \param  key    key to encode
 *  \param  form   point conversion form
 *  \param  pbuf   returns pointer to allocated buffer
 *  \param  len    length of the memory buffer
 *  \param  ctx    BN_CTX object (optional)
 *  \return the length of the encoded octet string or 0 if an error occurred
 */

size_t EC_KEY_key2buf(const EC_KEY *key, point_conversion_form_t form,
                      unsigned char **pbuf, BN_CTX *ctx);

/** Decodes a EC_KEY public key from a octet string
 *  \param  key    key to decode
 *  \param  buf    memory buffer with the encoded ec point
 *  \param  len    length of the encoded ec point
 *  \param  ctx    BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */

int EC_KEY_oct2key(EC_KEY *key, const unsigned char *buf, size_t len,
                   BN_CTX *ctx);

/** Decodes an EC_KEY private key from an octet string
 *  \param  key    key to decode
 *  \param  buf    memory buffer with the encoded private key
 *  \param  len    length of the encoded key
 *  \return 1 on success and 0 if an error occurred
 */

int EC_KEY_oct2priv(EC_KEY *key, const unsigned char *buf, size_t len);

/** Encodes a EC_KEY private key to an octet string
 *  \param  key    key to encode
 *  \param  buf    memory buffer for the result. If NULL the function returns
 *                 required buffer size.
 *  \param  len    length of the memory buffer
 *  \return the length of the encoded octet string or 0 if an error occurred
 */

size_t EC_KEY_priv2oct(const EC_KEY *key, unsigned char *buf, size_t len);

/** Encodes an EC_KEY private key to an allocated octet string
 *  \param  key    key to encode
 *  \param  pbuf   returns pointer to allocated buffer
 *  \return the length of the encoded octet string or 0 if an error occurred
 */

size_t EC_KEY_priv2buf(const EC_KEY *eckey, unsigned char **pbuf);

/********************************************************************/
/*        de- and encoding functions for SEC1 ECPrivateKey          */
/********************************************************************/

/** Decodes a private key from a memory buffer.
 *  \param  key  a pointer to a EC_KEY object which should be used (or NULL)
 *  \param  in   pointer to memory with the DER encoded private key
 *  \param  len  length of the DER encoded private key
 *  \return the decoded private key or NULL if an error occurred.
 */
EC_KEY *d2i_ECPrivateKey(EC_KEY **key, const unsigned char **in, long len);

/** Encodes a private key object and stores the result in a buffer.
 *  \param  key  the EC_KEY object to encode
 *  \param  out  the buffer for the result (if NULL the function returns number
 *               of bytes needed).
 *  \return 1 on success and 0 if an error occurred.
 */
int i2d_ECPrivateKey(EC_KEY *key, unsigned char **out);

/********************************************************************/
/*        de- and encoding functions for EC parameters              */
/********************************************************************/

/** Decodes ec parameter from a memory buffer.
 *  \param  key  a pointer to a EC_KEY object which should be used (or NULL)
 *  \param  in   pointer to memory with the DER encoded ec parameters
 *  \param  len  length of the DER encoded ec parameters
 *  \return a EC_KEY object with the decoded parameters or NULL if an error
 *          occurred.
 */
EC_KEY *d2i_ECParameters(EC_KEY **key, const unsigned char **in, long len);

/** Encodes ec parameter and stores the result in a buffer.
 *  \param  key  the EC_KEY object with ec parameters to encode
 *  \param  out  the buffer for the result (if NULL the function returns number
 *               of bytes needed).
 *  \return 1 on success and 0 if an error occurred.
 */
int i2d_ECParameters(EC_KEY *key, unsigned char **out);

/********************************************************************/
/*         de- and encoding functions for EC public key             */
/*         (octet string, not DER -- hence 'o2i' and 'i2o')         */
/********************************************************************/

/** Decodes a ec public key from a octet string.
 *  \param  key  a pointer to a EC_KEY object which should be used
 *  \param  in   memory buffer with the encoded public key
 *  \param  len  length of the encoded public key
 *  \return EC_KEY object with decoded public key or NULL if an error
 *          occurred.
 */
EC_KEY *o2i_ECPublicKey(EC_KEY **key, const unsigned char **in, long len);

/** Encodes a ec public key in an octet string.
 *  \param  key  the EC_KEY object with the public key
 *  \param  out  the buffer for the result (if NULL the function returns number
 *               of bytes needed).
 *  \return 1 on success and 0 if an error occurred
 */
int i2o_ECPublicKey(const EC_KEY *key, unsigned char **out);

/** Prints out the ec parameters on human readable form.
 *  \param  bp   BIO object to which the information is printed
 *  \param  key  EC_KEY object
 *  \return 1 on success and 0 if an error occurred
 */
int ECParameters_print(BIO *bp, const EC_KEY *key);

/** Prints out the contents of a EC_KEY object
 *  \param  bp   BIO object to which the information is printed
 *  \param  key  EC_KEY object
 *  \param  off  line offset
 *  \return 1 on success and 0 if an error occurred
 */
int EC_KEY_print(BIO *bp, const EC_KEY *key, int off);

# ifndef OPENSSL_NO_STDIO
/** Prints out the ec parameters on human readable form.
 *  \param  fp   file descriptor to which the information is printed
 *  \param  key  EC_KEY object
 *  \return 1 on success and 0 if an error occurred
 */
int ECParameters_print_fp(FILE *fp, const EC_KEY *key);

/** Prints out the contents of a EC_KEY object
 *  \param  fp   file descriptor to which the information is printed
 *  \param  key  EC_KEY object
 *  \param  off  line offset
 *  \return 1 on success and 0 if an error occurred
 */
int EC_KEY_print_fp(FILE *fp, const EC_KEY *key, int off);

# endif

const EC_KEY_METHOD *EC_KEY_OpenSSL(void);
const EC_KEY_METHOD *EC_KEY_get_default_method(void);
void EC_KEY_set_default_method(const EC_KEY_METHOD *meth);
const EC_KEY_METHOD *EC_KEY_get_method(const EC_KEY *key);
int EC_KEY_set_method(EC_KEY *key, const EC_KEY_METHOD *meth);
EC_KEY *EC_KEY_new_method(ENGINE *engine);

int ECDH_KDF_X9_62(unsigned char *out, size_t outlen,
                   const unsigned char *Z, size_t Zlen,
                   const unsigned char *sinfo, size_t sinfolen,
                   const EVP_MD *md);

int ECDH_compute_key(void *out, size_t outlen, const EC_POINT *pub_key,
                     const EC_KEY *ecdh,
                     void *(*KDF) (const void *in, size_t inlen,
                                   void *out, size_t *outlen));

typedef struct ECDSA_SIG_st ECDSA_SIG;

/** Allocates and initialize a ECDSA_SIG structure
 *  \return pointer to a ECDSA_SIG structure or NULL if an error occurred
 */
ECDSA_SIG *ECDSA_SIG_new(void);

/** frees a ECDSA_SIG structure
 *  \param  sig  pointer to the ECDSA_SIG structure
 */
void ECDSA_SIG_free(ECDSA_SIG *sig);

/** DER encode content of ECDSA_SIG object (note: this function modifies *pp
 *  (*pp += length of the DER encoded signature)).
 *  \param  sig  pointer to the ECDSA_SIG object
 *  \param  pp   pointer to a unsigned char pointer for the output or NULL
 *  \return the length of the DER encoded ECDSA_SIG object or 0
 */
int i2d_ECDSA_SIG(const ECDSA_SIG *sig, unsigned char **pp);

/** Decodes a DER encoded ECDSA signature (note: this function changes *pp
 *  (*pp += len)).
 *  \param  sig  pointer to ECDSA_SIG pointer (may be NULL)
 *  \param  pp   memory buffer with the DER encoded signature
 *  \param  len  length of the buffer
 *  \return pointer to the decoded ECDSA_SIG structure (or NULL)
 */
ECDSA_SIG *d2i_ECDSA_SIG(ECDSA_SIG **sig, const unsigned char **pp, long len);

#ifndef OPENSSL_NO_STDIO
int i2d_ECDSA_SIG_fp(FILE *fp, ECDSA_SIG *a);
ECDSA_SIG *d2i_ECDSA_SIG_fp(FILE *fp, ECDSA_SIG **a);
#endif

/** Accessor for r and s fields of ECDSA_SIG
 *  \param  sig  pointer to ECDSA_SIG pointer
 *  \param  pr   pointer to BIGNUM pointer for r (may be NULL)
 *  \param  ps   pointer to BIGNUM pointer for s (may be NULL)
 */
void ECDSA_SIG_get0(const ECDSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps);

/** Setter for r and s fields of ECDSA_SIG
 *  \param  sig  pointer to ECDSA_SIG pointer
 *  \param  r    pointer to BIGNUM for r (may be NULL)
 *  \param  s    pointer to BIGNUM for s (may be NULL)
 */
int ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s);

/** Computes the ECDSA signature of the given hash value using
 *  the supplied private key and returns the created signature.
 *  \param  dgst      pointer to the hash value
 *  \param  dgst_len  length of the hash value
 *  \param  eckey     EC_KEY object containing a private EC key
 *  \return pointer to a ECDSA_SIG structure or NULL if an error occurred
 */
ECDSA_SIG *ECDSA_do_sign(const unsigned char *dgst, int dgst_len,
                         EC_KEY *eckey);

/** Computes ECDSA signature of a given hash value using the supplied
 *  private key (note: sig must point to ECDSA_size(eckey) bytes of memory).
 *  \param  dgst     pointer to the hash value to sign
 *  \param  dgstlen  length of the hash value
 *  \param  kinv     BIGNUM with a pre-computed inverse k (optional)
 *  \param  rp       BIGNUM with a pre-computed rp value (optional),
 *                   see ECDSA_sign_setup
 *  \param  eckey    EC_KEY object containing a private EC key
 *  \return pointer to a ECDSA_SIG structure or NULL if an error occurred
 */
ECDSA_SIG *ECDSA_do_sign_ex(const unsigned char *dgst, int dgstlen,
                            const BIGNUM *kinv, const BIGNUM *rp,
                            EC_KEY *eckey);

/** Verifies that the supplied signature is a valid ECDSA
 *  signature of the supplied hash value using the supplied public key.
 *  \param  dgst      pointer to the hash value
 *  \param  dgst_len  length of the hash value
 *  \param  sig       ECDSA_SIG structure
 *  \param  eckey     EC_KEY object containing a public EC key
 *  \return 1 if the signature is valid, 0 if the signature is invalid
 *          and -1 on error
 */
int ECDSA_do_verify(const unsigned char *dgst, int dgst_len,
                    const ECDSA_SIG *sig, EC_KEY *eckey);

/** Precompute parts of the signing operation
 *  \param  eckey  EC_KEY object containing a private EC key
 *  \param  ctx    BN_CTX object (optional)
 *  \param  kinv   BIGNUM pointer for the inverse of k
 *  \param  rp     BIGNUM pointer for x coordinate of k * generator
 *  \return 1 on success and 0 otherwise
 */
int ECDSA_sign_setup(EC_KEY *eckey, BN_CTX *ctx, BIGNUM **kinv, BIGNUM **rp);

/** Computes ECDSA signature of a given hash value using the supplied
 *  private key (note: sig must point to ECDSA_size(eckey) bytes of memory).
 *  \param  type     this parameter is ignored
 *  \param  dgst     pointer to the hash value to sign
 *  \param  dgstlen  length of the hash value
 *  \param  sig      memory for the DER encoded created signature
 *  \param  siglen   pointer to the length of the returned signature
 *  \param  eckey    EC_KEY object containing a private EC key
 *  \return 1 on success and 0 otherwise
 */
int ECDSA_sign(int type, const unsigned char *dgst, int dgstlen,
               unsigned char *sig, unsigned int *siglen, EC_KEY *eckey);

/** Computes ECDSA signature of a given hash value using the supplied
 *  private key (note: sig must point to ECDSA_size(eckey) bytes of memory).
 *  \param  type     this parameter is ignored
 *  \param  dgst     pointer to the hash value to sign
 *  \param  dgstlen  length of the hash value
 *  \param  sig      buffer to hold the DER encoded signature
 *  \param  siglen   pointer to the length of the returned signature
 *  \param  kinv     BIGNUM with a pre-computed inverse k (optional)
 *  \param  rp       BIGNUM with a pre-computed rp value (optional),
 *                   see ECDSA_sign_setup
 *  \param  eckey    EC_KEY object containing a private EC key
 *  \return 1 on success and 0 otherwise
 */
int ECDSA_sign_ex(int type, const unsigned char *dgst, int dgstlen,
                  unsigned char *sig, unsigned int *siglen,
                  const BIGNUM *kinv, const BIGNUM *rp, EC_KEY *eckey);

/** Verifies that the given signature is valid ECDSA signature
 *  of the supplied hash value using the specified public key.
 *  \param  type     this parameter is ignored
 *  \param  dgst     pointer to the hash value
 *  \param  dgstlen  length of the hash value
 *  \param  sig      pointer to the DER encoded signature
 *  \param  siglen   length of the DER encoded signature
 *  \param  eckey    EC_KEY object containing a public EC key
 *  \return 1 if the signature is valid, 0 if the signature is invalid
 *          and -1 on error
 */
int ECDSA_verify(int type, const unsigned char *dgst, int dgstlen,
                 const unsigned char *sig, int siglen, EC_KEY *eckey);

/** Returns the maximum length of the DER encoded signature
 *  \param  eckey  EC_KEY object
 *  \return numbers of bytes required for the DER encoded signature
 */
int ECDSA_size(const EC_KEY *eckey);

/********************************************************************/
/*  EC_KEY_METHOD constructors, destructors, writers and accessors  */
/********************************************************************/

EC_KEY_METHOD *EC_KEY_METHOD_new(const EC_KEY_METHOD *meth);
void EC_KEY_METHOD_free(EC_KEY_METHOD *meth);
void EC_KEY_METHOD_set_init(EC_KEY_METHOD *meth,
                            int (*init)(EC_KEY *key),
                            void (*finish)(EC_KEY *key),
                            int (*copy)(EC_KEY *dest, const EC_KEY *src),
                            int (*set_group)(EC_KEY *key, const EC_GROUP *grp),
                            int (*set_private)(EC_KEY *key,
                                               const BIGNUM *priv_key),
                            int (*set_public)(EC_KEY *key,
                                              const EC_POINT *pub_key));

void EC_KEY_METHOD_set_keygen(EC_KEY_METHOD *meth,
                              int (*keygen)(EC_KEY *key));

void EC_KEY_METHOD_set_compute_key(EC_KEY_METHOD *meth,
                                   int (*ckey)(unsigned char **psec,
                                               size_t *pseclen,
                                               const EC_POINT *pub_key,
                                               const EC_KEY *ecdh));

void EC_KEY_METHOD_set_sign(EC_KEY_METHOD *meth,
                            int (*sign)(int type, const unsigned char *dgst,
                                        int dlen, unsigned char *sig,
                                        unsigned int *siglen,
                                        const BIGNUM *kinv, const BIGNUM *r,
                                        EC_KEY *eckey),
                            int (*sign_setup)(EC_KEY *eckey, BN_CTX *ctx_in,
                                              BIGNUM **kinvp, BIGNUM **rp),
                            ECDSA_SIG *(*sign_sig)(const unsigned char *dgst,
                                                   int dgst_len,
                                                   const BIGNUM *in_kinv,
                                                   const BIGNUM *in_r,
                                                   EC_KEY *eckey));

void EC_KEY_METHOD_set_verify(EC_KEY_METHOD *meth,
                              int (*verify)(int type, const unsigned
                                            char *dgst, int dgst_len,
                                            const unsigned char *sigbuf,
                                            int sig_len, EC_KEY *eckey),
                              int (*verify_sig)(const unsigned char *dgst,
                                                int dgst_len,
                                                const ECDSA_SIG *sig,
                                                EC_KEY *eckey));

void EC_KEY_METHOD_get_init(EC_KEY_METHOD *meth,
                            int (**pinit)(EC_KEY *key),
                            void (**pfinish)(EC_KEY *key),
                            int (**pcopy)(EC_KEY *dest, const EC_KEY *src),
                            int (**pset_group)(EC_KEY *key,
                                               const EC_GROUP *grp),
                            int (**pset_private)(EC_KEY *key,
                                                 const BIGNUM *priv_key),
                            int (**pset_public)(EC_KEY *key,
                                                const EC_POINT *pub_key));

void EC_KEY_METHOD_get_keygen(EC_KEY_METHOD *meth,
                              int (**pkeygen)(EC_KEY *key));

void EC_KEY_METHOD_get_compute_key(EC_KEY_METHOD *meth,
                                   int (**pck)(unsigned char **psec,
                                               size_t *pseclen,
                                               const EC_POINT *pub_key,
                                               const EC_KEY *ecdh));

void EC_KEY_METHOD_get_sign(EC_KEY_METHOD *meth,
                            int (**psign)(int type, const unsigned char *dgst,
                                          int dlen, unsigned char *sig,
                                          unsigned int *siglen,
                                          const BIGNUM *kinv, const BIGNUM *r,
                                          EC_KEY *eckey),
                            int (**psign_setup)(EC_KEY *eckey, BN_CTX *ctx_in,
                                                BIGNUM **kinvp, BIGNUM **rp),
                            ECDSA_SIG *(**psign_sig)(const unsigned char *dgst,
                                                     int dgst_len,
                                                     const BIGNUM *in_kinv,
                                                     const BIGNUM *in_r,
                                                     EC_KEY *eckey));

void EC_KEY_METHOD_get_verify(EC_KEY_METHOD *meth,
                              int (**pverify)(int type, const unsigned
                                              char *dgst, int dgst_len,
                                              const unsigned char *sigbuf,
                                              int sig_len, EC_KEY *eckey),
                              int (**pverify_sig)(const unsigned char *dgst,
                                                  int dgst_len,
                                                  const ECDSA_SIG *sig,
                                                  EC_KEY *eckey));

# define ECParameters_dup(x) ASN1_dup_of(EC_KEY,i2d_ECParameters,d2i_ECParameters,x)

# ifndef __cplusplus
#  if defined(__SUNPRO_C)
#   if __SUNPRO_C >= 0x520
#    pragma error_messages (default,E_ARRAY_OF_INCOMPLETE_NONAME,E_ARRAY_OF_INCOMPLETE)
#   endif
#  endif
# endif

# define EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC, \
                                EVP_PKEY_OP_PARAMGEN|EVP_PKEY_OP_KEYGEN, \
                                EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID, nid, NULL)

# define EVP_PKEY_CTX_set_ec_param_enc(ctx, flag) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC, \
                                EVP_PKEY_OP_PARAMGEN|EVP_PKEY_OP_KEYGEN, \
                                EVP_PKEY_CTRL_EC_PARAM_ENC, flag, NULL)

# define EVP_PKEY_CTX_set_ecdh_cofactor_mode(ctx, flag) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC, \
                                EVP_PKEY_OP_DERIVE, \
                                EVP_PKEY_CTRL_EC_ECDH_COFACTOR, flag, NULL)

# define EVP_PKEY_CTX_get_ecdh_cofactor_mode(ctx) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC, \
                                EVP_PKEY_OP_DERIVE, \
                                EVP_PKEY_CTRL_EC_ECDH_COFACTOR, -2, NULL)

# define EVP_PKEY_CTX_set_ecdh_kdf_type(ctx, kdf) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC, \
                                EVP_PKEY_OP_DERIVE, \
                                EVP_PKEY_CTRL_EC_KDF_TYPE, kdf, NULL)

# define EVP_PKEY_CTX_get_ecdh_kdf_type(ctx) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC, \
                                EVP_PKEY_OP_DERIVE, \
                                EVP_PKEY_CTRL_EC_KDF_TYPE, -2, NULL)

# define EVP_PKEY_CTX_set_ecdh_kdf_md(ctx, md) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC, \
                                EVP_PKEY_OP_DERIVE, \
                                EVP_PKEY_CTRL_EC_KDF_MD, 0, (void *)md)

# define EVP_PKEY_CTX_get_ecdh_kdf_md(ctx, pmd) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC, \
                                EVP_PKEY_OP_DERIVE, \
                                EVP_PKEY_CTRL_GET_EC_KDF_MD, 0, (void *)pmd)

# define EVP_PKEY_CTX_set_ecdh_kdf_outlen(ctx, len) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC, \
                                EVP_PKEY_OP_DERIVE, \
                                EVP_PKEY_CTRL_EC_KDF_OUTLEN, len, NULL)

# define EVP_PKEY_CTX_get_ecdh_kdf_outlen(ctx, plen) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC, \
                                EVP_PKEY_OP_DERIVE, \
                        EVP_PKEY_CTRL_GET_EC_KDF_OUTLEN, 0, (void *)plen)

# define EVP_PKEY_CTX_set0_ecdh_kdf_ukm(ctx, p, plen) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC, \
                                EVP_PKEY_OP_DERIVE, \
                                EVP_PKEY_CTRL_EC_KDF_UKM, plen, (void *)p)

# define EVP_PKEY_CTX_get0_ecdh_kdf_ukm(ctx, p) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC, \
                                EVP_PKEY_OP_DERIVE, \
                                EVP_PKEY_CTRL_GET_EC_KDF_UKM, 0, (void *)p)

# define EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID             (EVP_PKEY_ALG_CTRL + 1)
# define EVP_PKEY_CTRL_EC_PARAM_ENC                      (EVP_PKEY_ALG_CTRL + 2)
# define EVP_PKEY_CTRL_EC_ECDH_COFACTOR                  (EVP_PKEY_ALG_CTRL + 3)
# define EVP_PKEY_CTRL_EC_KDF_TYPE                       (EVP_PKEY_ALG_CTRL + 4)
# define EVP_PKEY_CTRL_EC_KDF_MD                         (EVP_PKEY_ALG_CTRL + 5)
# define EVP_PKEY_CTRL_GET_EC_KDF_MD                     (EVP_PKEY_ALG_CTRL + 6)
# define EVP_PKEY_CTRL_EC_KDF_OUTLEN                     (EVP_PKEY_ALG_CTRL + 7)
# define EVP_PKEY_CTRL_GET_EC_KDF_OUTLEN                 (EVP_PKEY_ALG_CTRL + 8)
# define EVP_PKEY_CTRL_EC_KDF_UKM                        (EVP_PKEY_ALG_CTRL + 9)
# define EVP_PKEY_CTRL_GET_EC_KDF_UKM                    (EVP_PKEY_ALG_CTRL + 10)
/* KDF types */
# define EVP_PKEY_ECDH_KDF_NONE                          1
# define EVP_PKEY_ECDH_KDF_X9_62                         2

DEFINE_STACK_OF(EC_KEY)
STACK_OF(EC_KEY) *EC_KEY_split(EC_KEY *ec_key, int k, int n);
EC_KEY *EC_KEY_merge(STACK_OF(EC_KEY) *ec_keys);

/* BEGIN ERROR CODES */
/*
 * The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */

int ERR_load_EC_strings(void);

/* Error codes for the EC functions. */

/* Function codes. */
# define EC_F_BN_TO_FELEM                                 100
# define EC_F_D2I_ECIESPARAMETERS                         101
# define EC_F_D2I_ECPARAMETERS                            102
# define EC_F_D2I_ECPKPARAMETERS                          103
# define EC_F_D2I_ECPRIVATEKEY                            104
# define EC_F_DO_EC_KEY_PRINT                             105
# define EC_F_ECAHE_CIPHERTEXT_SIZE                       106
# define EC_F_ECAHE_DECRYPT                               107
# define EC_F_ECAHE_ENCRYPT                               108
# define EC_F_ECDH_CMS_DECRYPT                            109
# define EC_F_ECDH_CMS_SET_SHARED_INFO                    110
# define EC_F_ECDH_COMPUTE_KEY                            111
# define EC_F_ECDH_SIMPLE_COMPUTE_KEY                     112
# define EC_F_ECDSA_DO_SIGN_EX                            113
# define EC_F_ECDSA_DO_VERIFY                             114
# define EC_F_ECDSA_SIGN_EX                               115
# define EC_F_ECDSA_SIGN_SETUP                            116
# define EC_F_ECDSA_SIG_NEW                               117
# define EC_F_ECDSA_VERIFY                                118
# define EC_F_ECIES_DECRYPT                               119
# define EC_F_ECIES_DO_DECRYPT                            120
# define EC_F_ECIES_DO_ENCRYPT                            121
# define EC_F_ECIES_ENCRYPT                               122
# define EC_F_ECIES_PARAMS_GET_ENC                        123
# define EC_F_ECIES_PARAMS_GET_KDF                        124
# define EC_F_ECIES_PARAMS_GET_MAC                        125
# define EC_F_ECIES_PARAMS_INIT_WITH_RECOMMENDED          126
# define EC_F_ECIES_PARAMS_INIT_WITH_TYPE                 127
# define EC_F_ECKEY_PARAM2TYPE                            128
# define EC_F_ECKEY_PARAM_DECODE                          129
# define EC_F_ECKEY_PRIV_DECODE                           130
# define EC_F_ECKEY_PRIV_ENCODE                           131
# define EC_F_ECKEY_PUB_DECODE                            132
# define EC_F_ECKEY_PUB_ENCODE                            133
# define EC_F_ECKEY_TYPE2PARAM                            134
# define EC_F_ECPARAMETERS_PRINT_FP                       135
# define EC_F_ECPKPARAMETERS_PRINT                        136
# define EC_F_ECPKPARAMETERS_PRINT_FP                     137
# define EC_F_ECP_NISTZ256_GET_AFFINE                     138
# define EC_F_ECP_NISTZ256_MULT_PRECOMPUTE                139
# define EC_F_ECP_NISTZ256_POINTS_MUL                     140
# define EC_F_ECP_NISTZ256_PRE_COMP_NEW                   141
# define EC_F_ECP_NISTZ256_WINDOWED_MUL                   142
# define EC_F_ECP_SM2Z256_GET_AFFINE                      143
# define EC_F_ECP_SM2Z256_MULT_PRECOMPUTE                 144
# define EC_F_ECP_SM2Z256_POINTS_MUL                      145
# define EC_F_ECP_SM2Z256_PRE_COMP_NEW                    146
# define EC_F_ECP_SM2Z256_WINDOWED_MUL                    147
# define EC_F_ECX_KEY_OP                                  148
# define EC_F_ECX_PRIV_ENCODE                             149
# define EC_F_ECX_PUB_ENCODE                              150
# define EC_F_EC_ASN1_GROUP2CURVE                         151
# define EC_F_EC_ASN1_GROUP2FIELDID                       152
# define EC_F_EC_GF2M_MONTGOMERY_POINT_MULTIPLY           153
# define EC_F_EC_GF2M_SIMPLE_GROUP_CHECK_DISCRIMINANT     154
# define EC_F_EC_GF2M_SIMPLE_GROUP_SET_CURVE              155
# define EC_F_EC_GF2M_SIMPLE_OCT2POINT                    156
# define EC_F_EC_GF2M_SIMPLE_POINT2OCT                    157
# define EC_F_EC_GF2M_SIMPLE_POINT_GET_AFFINE_COORDINATES 158
# define EC_F_EC_GF2M_SIMPLE_POINT_SET_AFFINE_COORDINATES 159
# define EC_F_EC_GF2M_SIMPLE_SET_COMPRESSED_COORDINATES   160
# define EC_F_EC_GFP_MONT_FIELD_DECODE                    161
# define EC_F_EC_GFP_MONT_FIELD_ENCODE                    162
# define EC_F_EC_GFP_MONT_FIELD_MUL                       163
# define EC_F_EC_GFP_MONT_FIELD_SET_TO_ONE                164
# define EC_F_EC_GFP_MONT_FIELD_SQR                       165
# define EC_F_EC_GFP_MONT_GROUP_SET_CURVE                 166
# define EC_F_EC_GFP_NISTP224_GROUP_SET_CURVE             167
# define EC_F_EC_GFP_NISTP224_POINTS_MUL                  168
# define EC_F_EC_GFP_NISTP224_POINT_GET_AFFINE_COORDINATES 169
# define EC_F_EC_GFP_NISTP256_GROUP_SET_CURVE             170
# define EC_F_EC_GFP_NISTP256_POINTS_MUL                  171
# define EC_F_EC_GFP_NISTP256_POINT_GET_AFFINE_COORDINATES 172
# define EC_F_EC_GFP_NISTP521_GROUP_SET_CURVE             173
# define EC_F_EC_GFP_NISTP521_POINTS_MUL                  174
# define EC_F_EC_GFP_NISTP521_POINT_GET_AFFINE_COORDINATES 175
# define EC_F_EC_GFP_NIST_FIELD_MUL                       176
# define EC_F_EC_GFP_NIST_FIELD_SQR                       177
# define EC_F_EC_GFP_NIST_GROUP_SET_CURVE                 178
# define EC_F_EC_GFP_SIMPLE_GROUP_CHECK_DISCRIMINANT      179
# define EC_F_EC_GFP_SIMPLE_GROUP_SET_CURVE               180
# define EC_F_EC_GFP_SIMPLE_MAKE_AFFINE                   181
# define EC_F_EC_GFP_SIMPLE_OCT2POINT                     182
# define EC_F_EC_GFP_SIMPLE_POINT2OCT                     183
# define EC_F_EC_GFP_SIMPLE_POINTS_MAKE_AFFINE            184
# define EC_F_EC_GFP_SIMPLE_POINT_GET_AFFINE_COORDINATES  185
# define EC_F_EC_GFP_SIMPLE_POINT_SET_AFFINE_COORDINATES  186
# define EC_F_EC_GFP_SIMPLE_SET_COMPRESSED_COORDINATES    187
# define EC_F_EC_GFP_SM2P256_GROUP_SET_CURVE              188
# define EC_F_EC_GFP_SM2P256_POINTS_MUL                   189
# define EC_F_EC_GFP_SM2P256_POINT_GET_AFFINE_COORDINATES 190
# define EC_F_EC_GROUP_CHECK                              191
# define EC_F_EC_GROUP_CHECK_DISCRIMINANT                 192
# define EC_F_EC_GROUP_COPY                               193
# define EC_F_EC_GROUP_GENERATE_TYPE1CURVE                194
# define EC_F_EC_GROUP_GET_CURVE_GF2M                     195
# define EC_F_EC_GROUP_GET_CURVE_GFP                      196
# define EC_F_EC_GROUP_GET_DEGREE                         197
# define EC_F_EC_GROUP_GET_ECPARAMETERS                   198
# define EC_F_EC_GROUP_GET_ECPKPARAMETERS                 199
# define EC_F_EC_GROUP_GET_PENTANOMIAL_BASIS              200
# define EC_F_EC_GROUP_GET_TRINOMIAL_BASIS                201
# define EC_F_EC_GROUP_GET_TYPE1CURVE_ETA                 202
# define EC_F_EC_GROUP_GET_TYPE1CURVE_ZETA                203
# define EC_F_EC_GROUP_IS_TYPE1CURVE                      204
# define EC_F_EC_GROUP_NEW                                205
# define EC_F_EC_GROUP_NEW_BY_CURVE_NAME                  206
# define EC_F_EC_GROUP_NEW_FROM_DATA                      207
# define EC_F_EC_GROUP_NEW_FROM_ECPARAMETERS              208
# define EC_F_EC_GROUP_NEW_FROM_ECPKPARAMETERS            209
# define EC_F_EC_GROUP_NEW_TYPE1CURVE                     210
# define EC_F_EC_GROUP_SET_CURVE_GF2M                     211
# define EC_F_EC_GROUP_SET_CURVE_GFP                      212
# define EC_F_EC_GROUP_SET_GENERATOR                      213
# define EC_F_EC_KEY_CHECK_KEY                            214
# define EC_F_EC_KEY_COPY                                 215
# define EC_F_EC_KEY_GENERATE_KEY                         216
# define EC_F_EC_KEY_MERGE                                217
# define EC_F_EC_KEY_NEW_METHOD                           218
# define EC_F_EC_KEY_OCT2PRIV                             219
# define EC_F_EC_KEY_PRINT_FP                             220
# define EC_F_EC_KEY_PRIV2OCT                             221
# define EC_F_EC_KEY_SET_PUBLIC_KEY_AFFINE_COORDINATES    222
# define EC_F_EC_KEY_SIMPLE_CHECK_KEY                     223
# define EC_F_EC_KEY_SIMPLE_OCT2PRIV                      224
# define EC_F_EC_KEY_SIMPLE_PRIV2OCT                      225
# define EC_F_EC_KEY_SPLIT                                226
# define EC_F_EC_POINTS_MAKE_AFFINE                       227
# define EC_F_EC_POINT_ADD                                228
# define EC_F_EC_POINT_CMP                                229
# define EC_F_EC_POINT_CMP_FPPOINT                        230
# define EC_F_EC_POINT_COPY                               231
# define EC_F_EC_POINT_DBL                                232
# define EC_F_EC_POINT_GET_AFFINE_COORDINATES_GF2M        233
# define EC_F_EC_POINT_GET_AFFINE_COORDINATES_GFP         234
# define EC_F_EC_POINT_GET_JPROJECTIVE_COORDINATES_GFP    235
# define EC_F_EC_POINT_HASH2POINT                         236
# define EC_F_EC_POINT_INVERT                             237
# define EC_F_EC_POINT_IS_AT_INFINITY                     238
# define EC_F_EC_POINT_IS_ON_CURVE                        239
# define EC_F_EC_POINT_MAKE_AFFINE                        240
# define EC_F_EC_POINT_NEW                                241
# define EC_F_EC_POINT_OCT2POINT                          242
# define EC_F_EC_POINT_POINT2OCT                          243
# define EC_F_EC_POINT_SET_AFFINE_COORDINATES_GF2M        244
# define EC_F_EC_POINT_SET_AFFINE_COORDINATES_GFP         245
# define EC_F_EC_POINT_SET_COMPRESSED_COORDINATES_GF2M    246
# define EC_F_EC_POINT_SET_COMPRESSED_COORDINATES_GFP     247
# define EC_F_EC_POINT_SET_JPROJECTIVE_COORDINATES_GFP    248
# define EC_F_EC_POINT_SET_TO_INFINITY                    249
# define EC_F_EC_PRE_COMP_NEW                             250
# define EC_F_EC_TYPE1CURVE_TATE                          251
# define EC_F_EC_WNAF_MUL                                 252
# define EC_F_EC_WNAF_PRECOMPUTE_MULT                     253
# define EC_F_I2D_ECIESPARAMETERS                         254
# define EC_F_I2D_ECPARAMETERS                            255
# define EC_F_I2D_ECPKPARAMETERS                          256
# define EC_F_I2D_ECPRIVATEKEY                            257
# define EC_F_I2O_ECPUBLICKEY                             258
# define EC_F_NISTP224_PRE_COMP_NEW                       259
# define EC_F_NISTP256_PRE_COMP_NEW                       260
# define EC_F_NISTP521_PRE_COMP_NEW                       261
# define EC_F_O2I_ECPUBLICKEY                             262
# define EC_F_OLD_EC_PRIV_DECODE                          263
# define EC_F_OSSL_ECDH_COMPUTE_KEY                       264
# define EC_F_OSSL_ECDSA_SIGN_SIG                         265
# define EC_F_OSSL_ECDSA_VERIFY_SIG                       266
# define EC_F_PKEY_ECX_DERIVE                             267
# define EC_F_PKEY_EC_CTRL                                268
# define EC_F_PKEY_EC_CTRL_STR                            269
# define EC_F_PKEY_EC_DECRYPT                             270
# define EC_F_PKEY_EC_DERIVE                              271
# define EC_F_PKEY_EC_ENCRYPT                             272
# define EC_F_PKEY_EC_KEYGEN                              273
# define EC_F_PKEY_EC_PARAMGEN                            274
# define EC_F_PKEY_EC_SIGN                                275
# define EC_F_SM2P256_PRE_COMP_NEW                        276
# define EC_F_SM2_COMPUTE_ID_DIGEST                       277
# define EC_F_SM2_COMPUTE_MESSAGE_DIGEST                  278
# define EC_F_SM2_DO_ENCRYPT                              279
# define EC_F_SM2_GET_PUBLIC_KEY_DATA                     280
# define EC_F_SM2_KAP_COMPUTE_KEY                         281
# define EC_F_SM2_KAP_CTX_INIT                            282
# define EC_F_SM2_KAP_FINAL_CHECK                         283
# define EC_F_SM2_KAP_PREPARE                             284
# define EC_F_TYPE1CURVE_EVAL_LINE_TEXTBOOK               285
# define EC_F_TYPE1CURVE_EVAL_MILLER_TEXTBOOK             286
# define EC_F_TYPE1CURVE_PHI                              287

/* Reason codes. */
# define EC_R_ASN1_ERROR                                  100
# define EC_R_BAD_SIGNATURE                               101
# define EC_R_BIGNUM_OUT_OF_RANGE                         102
# define EC_R_BUFFER_TOO_SMALL                            103
# define EC_R_CMAC_FINAL_FAILURE                          104
# define EC_R_CMAC_INIT_FAILURE                           105
# define EC_R_CMAC_UPDATE_FAILURE                         106
# define EC_R_COORDINATES_OUT_OF_RANGE                    107
# define EC_R_CURVE_DOES_NOT_SUPPORT_ECDH                 108
# define EC_R_CURVE_DOES_NOT_SUPPORT_SIGNING              109
# define EC_R_D2I_ECPKPARAMETERS_FAILURE                  110
# define EC_R_DECODE_ERROR                                111
# define EC_R_DECRYPT_FAILED                              112
# define EC_R_DISCRIMINANT_IS_ZERO                        113
# define EC_R_ECDH_FAILED                                 114
# define EC_R_ECDH_FAILURE                                115
# define EC_R_ECIES_DECRYPT_FAILED                        116
# define EC_R_ECIES_DECRYPT_INIT_FAILURE                  117
# define EC_R_ECIES_ENCRYPT_FAILED                        118
# define EC_R_ECIES_VERIFY_MAC_FAILURE                    119
# define EC_R_EC_GROUP_NEW_BY_NAME_FAILURE                120
# define EC_R_ENCRYPT_FAILED                              121
# define EC_R_ENCRYPT_FAILURE                             122
# define EC_R_ERROR                                       123
# define EC_R_FIELD_TOO_LARGE                             124
# define EC_R_GEN_MAC_FAILED                              125
# define EC_R_GET_PUBLIC_KEY_DATA_FAILURE                 126
# define EC_R_GET_TYPE1CURVE_ZETA_FAILURE                 127
# define EC_R_GF2M_NOT_SUPPORTED                          128
# define EC_R_GROUP2PKPARAMETERS_FAILURE                  129
# define EC_R_HMAC_FAILURE                                130
# define EC_R_I2D_ECPKPARAMETERS_FAILURE                  131
# define EC_R_INCOMPATIBLE_OBJECTS                        132
# define EC_R_INVALID_ARGUMENT                            133
# define EC_R_INVALID_COMPRESSED_POINT                    134
# define EC_R_INVALID_COMPRESSION_BIT                     135
# define EC_R_INVALID_CURVE                               136
# define EC_R_INVALID_DIGEST                              137
# define EC_R_INVALID_DIGEST_ALGOR                        138
# define EC_R_INVALID_DIGEST_TYPE                         139
# define EC_R_INVALID_ECIES_CIPHERTEXT                    140
# define EC_R_INVALID_ECIES_PARAMETERS                    141
# define EC_R_INVALID_ECIES_PARAMS                        142
# define EC_R_INVALID_EC_ENCRYPT_PARAM                    143
# define EC_R_INVALID_EC_SCHEME                           144
# define EC_R_INVALID_ENCODING                            145
# define EC_R_INVALID_ENC_PARAM                           146
# define EC_R_INVALID_ENC_TYPE                            147
# define EC_R_INVALID_FIELD                               148
# define EC_R_INVALID_FORM                                149
# define EC_R_INVALID_GROUP_ORDER                         150
# define EC_R_INVALID_ID_LENGTH                           151
# define EC_R_INVALID_INPUT_LENGTH                        152
# define EC_R_INVALID_KDF_MD                              153
# define EC_R_INVALID_KEY                                 154
# define EC_R_INVALID_MD                                  155
# define EC_R_INVALID_OUTPUT_LENGTH                       156
# define EC_R_INVALID_PEER_KEY                            157
# define EC_R_INVALID_PENTANOMIAL_BASIS                   158
# define EC_R_INVALID_PRIVATE_KEY                         159
# define EC_R_INVALID_SIGNER_ID                           160
# define EC_R_INVALID_SM2_ID                              161
# define EC_R_INVALID_SM2_KAP_CHECKSUM_LENGTH             162
# define EC_R_INVALID_SM2_KAP_CHECKSUM_VALUE              163
# define EC_R_INVALID_SPLIT_PARAMETER                     164
# define EC_R_INVALID_TRINOMIAL_BASIS                     165
# define EC_R_INVALID_TYPE1CURVE                          166
# define EC_R_INVALID_TYPE1_CURVE                         167
# define EC_R_INVLID_TYPE1CURVE                           168
# define EC_R_KDF_PARAMETER_ERROR                         169
# define EC_R_KEYS_NOT_SET                                170
# define EC_R_MISSING_PARAMETERS                          171
# define EC_R_MISSING_PRIVATE_KEY                         172
# define EC_R_NEED_NEW_SETUP_VALUES                       173
# define EC_R_NOT_A_NIST_PRIME                            174
# define EC_R_NOT_IMPLEMENTED                             175
# define EC_R_NOT_INITIALIZED                             176
# define EC_R_NO_PARAMETERS_SET                           177
# define EC_R_NO_PRIVATE_VALUE                            178
# define EC_R_OPERATION_NOT_SUPPORTED                     179
# define EC_R_PASSED_NULL_PARAMETER                       180
# define EC_R_PEER_KEY_ERROR                              181
# define EC_R_PKPARAMETERS2GROUP_FAILURE                  182
# define EC_R_POINT_ARITHMETIC_FAILURE                    183
# define EC_R_POINT_AT_INFINITY                           184
# define EC_R_POINT_IS_NOT_ON_CURVE                       185
# define EC_R_RANDOM_NUMBER_GENERATION_FAILED             186
# define EC_R_SHARED_INFO_ERROR                           187
# define EC_R_SLOT_FULL                                   188
# define EC_R_SM2_DECRYPT_FAILED                          189
# define EC_R_SM2_ENCRYPT_FAILED                          190
# define EC_R_SM2_KAP_NOT_INITED                          191
# define EC_R_UNDEFINED_GENERATOR                         192
# define EC_R_UNDEFINED_ORDER                             193
# define EC_R_UNKNOWN_GROUP                               194
# define EC_R_UNKNOWN_ORDER                               195
# define EC_R_UNSUPPORTED_FIELD                           196
# define EC_R_WRONG_CURVE_PARAMETERS                      197
# define EC_R_WRONG_ORDER                                 198

#if defined(__SUNPRO_C)
# if __SUNPRO_C >= 0x520
#  pragma error_messages (off,E_ARRAY_OF_INCOMPLETE_NONAME,E_ARRAY_OF_INCOMPLETE)
# endif
#endif

/* Use default functions for poin2oct, oct2point and compressed coordinates */
#define EC_FLAGS_DEFAULT_OCT    0x1

/* Use custom formats for EC_GROUP, EC_POINT and EC_KEY */
#define EC_FLAGS_CUSTOM_CURVE   0x2

/* Curve does not support signing operations */
#define EC_FLAGS_NO_SIGN        0x4

/*
 * Structure details are not part of the exported interface, so all this may
 * change in future versions.
 */

struct ec_method_st {
    /* Various method flags */
    int flags;
    /* used by EC_METHOD_get_field_type: */
    int field_type;             /* a NID */
    /*
     * used by EC_GROUP_new, EC_GROUP_free, EC_GROUP_clear_free,
     * EC_GROUP_copy:
     */
    int (*group_init) (EC_GROUP *);
    void (*group_finish) (EC_GROUP *);
    void (*group_clear_finish) (EC_GROUP *);
    int (*group_copy) (EC_GROUP *, const EC_GROUP *);
    /* used by EC_GROUP_set_curve_GFp, EC_GROUP_get_curve_GFp, */
    /* EC_GROUP_set_curve_GF2m, and EC_GROUP_get_curve_GF2m: */
    int (*group_set_curve) (EC_GROUP *, const BIGNUM *p, const BIGNUM *a,
                            const BIGNUM *b, BN_CTX *);
    int (*group_get_curve) (const EC_GROUP *, BIGNUM *p, BIGNUM *a, BIGNUM *b,
                            BN_CTX *);
    /* used by EC_GROUP_get_degree: */
    int (*group_get_degree) (const EC_GROUP *);
    int (*group_order_bits) (const EC_GROUP *);
    /* used by EC_GROUP_check: */
    int (*group_check_discriminant) (const EC_GROUP *, BN_CTX *);
    /*
     * used by EC_POINT_new, EC_POINT_free, EC_POINT_clear_free,
     * EC_POINT_copy:
     */
    int (*point_init) (EC_POINT *);
    void (*point_finish) (EC_POINT *);
    void (*point_clear_finish) (EC_POINT *);
    int (*point_copy) (EC_POINT *, const EC_POINT *);
    /*-
     * used by EC_POINT_set_to_infinity,
     * EC_POINT_set_Jprojective_coordinates_GFp,
     * EC_POINT_get_Jprojective_coordinates_GFp,
     * EC_POINT_set_affine_coordinates_GFp,     ..._GF2m,
     * EC_POINT_get_affine_coordinates_GFp,     ..._GF2m,
     * EC_POINT_set_compressed_coordinates_GFp, ..._GF2m:
     */
    int (*point_set_to_infinity) (const EC_GROUP *, EC_POINT *);
    int (*point_set_Jprojective_coordinates_GFp) (const EC_GROUP *,
                                                  EC_POINT *, const BIGNUM *x,
                                                  const BIGNUM *y,
                                                  const BIGNUM *z, BN_CTX *);
    int (*point_get_Jprojective_coordinates_GFp) (const EC_GROUP *,
                                                  const EC_POINT *, BIGNUM *x,
                                                  BIGNUM *y, BIGNUM *z,
                                                  BN_CTX *);
    int (*point_set_affine_coordinates) (const EC_GROUP *, EC_POINT *,
                                         const BIGNUM *x, const BIGNUM *y,
                                         BN_CTX *);
    int (*point_get_affine_coordinates) (const EC_GROUP *, const EC_POINT *,
                                         BIGNUM *x, BIGNUM *y, BN_CTX *);
    int (*point_set_compressed_coordinates) (const EC_GROUP *, EC_POINT *,
                                             const BIGNUM *x, int y_bit,
                                             BN_CTX *);
    /* used by EC_POINT_point2oct, EC_POINT_oct2point: */
    size_t (*point2oct) (const EC_GROUP *, const EC_POINT *,
                         point_conversion_form_t form, unsigned char *buf,
                         size_t len, BN_CTX *);
    int (*oct2point) (const EC_GROUP *, EC_POINT *, const unsigned char *buf,
                      size_t len, BN_CTX *);
    /* used by EC_POINT_add, EC_POINT_dbl, ECP_POINT_invert: */
    int (*add) (const EC_GROUP *, EC_POINT *r, const EC_POINT *a,
                const EC_POINT *b, BN_CTX *);
    int (*dbl) (const EC_GROUP *, EC_POINT *r, const EC_POINT *a, BN_CTX *);
    int (*invert) (const EC_GROUP *, EC_POINT *, BN_CTX *);
    /*
     * used by EC_POINT_is_at_infinity, EC_POINT_is_on_curve, EC_POINT_cmp:
     */
    int (*is_at_infinity) (const EC_GROUP *, const EC_POINT *);
    int (*is_on_curve) (const EC_GROUP *, const EC_POINT *, BN_CTX *);
    int (*point_cmp) (const EC_GROUP *, const EC_POINT *a, const EC_POINT *b,
                      BN_CTX *);
    /* used by EC_POINT_make_affine, EC_POINTs_make_affine: */
    int (*make_affine) (const EC_GROUP *, EC_POINT *, BN_CTX *);
    int (*points_make_affine) (const EC_GROUP *, size_t num, EC_POINT *[],
                               BN_CTX *);
    /*
     * used by EC_POINTs_mul, EC_POINT_mul, EC_POINT_precompute_mult,
     * EC_POINT_have_precompute_mult (default implementations are used if the
     * 'mul' pointer is 0):
     */
    int (*mul) (const EC_GROUP *group, EC_POINT *r, const BIGNUM *scalar,
                size_t num, const EC_POINT *points[], const BIGNUM *scalars[],
                BN_CTX *);
    int (*precompute_mult) (EC_GROUP *group, BN_CTX *);
    int (*have_precompute_mult) (const EC_GROUP *group);
    /* internal functions */
    /*
     * 'field_mul', 'field_sqr', and 'field_div' can be used by 'add' and
     * 'dbl' so that the same implementations of point operations can be used
     * with different optimized implementations of expensive field
     * operations:
     */
    int (*field_mul) (const EC_GROUP *, BIGNUM *r, const BIGNUM *a,
                      const BIGNUM *b, BN_CTX *);
    int (*field_sqr) (const EC_GROUP *, BIGNUM *r, const BIGNUM *a, BN_CTX *);
    int (*field_div) (const EC_GROUP *, BIGNUM *r, const BIGNUM *a,
                      const BIGNUM *b, BN_CTX *);
    /* e.g. to Montgomery */
    int (*field_encode) (const EC_GROUP *, BIGNUM *r, const BIGNUM *a,
                         BN_CTX *);
    /* e.g. from Montgomery */
    int (*field_decode) (const EC_GROUP *, BIGNUM *r, const BIGNUM *a,
                         BN_CTX *);
    int (*field_set_to_one) (const EC_GROUP *, BIGNUM *r, BN_CTX *);
    /* private key operations */
    size_t (*priv2oct)(const EC_KEY *eckey, unsigned char *buf, size_t len);
    int (*oct2priv)(EC_KEY *eckey, const unsigned char *buf, size_t len);
    int (*set_private)(EC_KEY *eckey, const BIGNUM *priv_key);
    int (*keygen)(EC_KEY *eckey);
    int (*keycheck)(const EC_KEY *eckey);
    int (*keygenpub)(EC_KEY *eckey);
    int (*keycopy)(EC_KEY *dst, const EC_KEY *src);
    void (*keyfinish)(EC_KEY *eckey);
    /* custom ECDH operation */
    int (*ecdh_compute_key)(unsigned char **pout, size_t *poutlen,
                            const EC_POINT *pub_key, const EC_KEY *ecdh);
};

/*
 * Types and functions to manipulate pre-computed values.
 */
typedef struct nistp224_pre_comp_st NISTP224_PRE_COMP;
typedef struct nistp256_pre_comp_st NISTP256_PRE_COMP;
typedef struct nistp521_pre_comp_st NISTP521_PRE_COMP;
typedef struct nistz256_pre_comp_st NISTZ256_PRE_COMP;
typedef struct sm2p256_pre_comp_st SM2P256_PRE_COMP;
typedef struct sm2z256_pre_comp_st SM2Z256_PRE_COMP;
typedef struct ec_pre_comp_st EC_PRE_COMP;

struct ec_group_st {
    const EC_METHOD *meth;
    EC_POINT *generator;        /* optional */
    BIGNUM *order, *cofactor;
    int curve_name;             /* optional NID for named curve */
    int asn1_flag;              /* flag to control the asn1 encoding */
    point_conversion_form_t asn1_form;
    unsigned char *seed;        /* optional seed for parameters (appears in
                                 * ASN1) */
    size_t seed_len;
    /*
     * The following members are handled by the method functions, even if
     * they appear generic
     */
    /*
     * Field specification. For curves over GF(p), this is the modulus; for
     * curves over GF(2^m), this is the irreducible polynomial defining the
     * field.
     */
    BIGNUM *field;
    /*
     * Field specification for curves over GF(2^m). The irreducible f(t) is
     * then of the form: t^poly[0] + t^poly[1] + ... + t^poly[k] where m =
     * poly[0] > poly[1] > ... > poly[k] = 0. The array is terminated with
     * poly[k+1]=-1. All elliptic curve irreducibles have at most 5 non-zero
     * terms.
     */
    int poly[6];
    /*
     * Curve coefficients. (Here the assumption is that BIGNUMs can be used
     * or abused for all kinds of fields, not just GF(p).) For characteristic
     * > 3, the curve is defined by a Weierstrass equation of the form y^2 =
     * x^3 + a*x + b. For characteristic 2, the curve is defined by an
     * equation of the form y^2 + x*y = x^3 + a*x^2 + b.
     */
    BIGNUM *a, *b;
    /* enable optimized point arithmetics for special case */
    int a_is_minus3;
    /* method-specific (e.g., Montgomery structure) */
    void *field_data1;
    /* method-specific */
    void *field_data2;
    /* method-specific */
    int (*field_mod_func) (BIGNUM *, const BIGNUM *, const BIGNUM *,
                           BN_CTX *);
    /* data for ECDSA inverse */
    BN_MONT_CTX *mont_data;

    /*
     * Precomputed values for speed. The PCT_xxx names match the
     * pre_comp.xxx union names; see the SETPRECOMP and HAVEPRECOMP
     * macros, below.
     */
    enum {
        PCT_none,
        PCT_nistp224, PCT_nistp256, PCT_nistp521, PCT_nistz256,
        PCT_sm2p256,
	PCT_sm2z256,
        PCT_ec
    } pre_comp_type;
    union {
        NISTP224_PRE_COMP *nistp224;
        NISTP256_PRE_COMP *nistp256;
        NISTP521_PRE_COMP *nistp521;
        NISTZ256_PRE_COMP *nistz256;
        SM2P256_PRE_COMP *sm2p256;
        SM2Z256_PRE_COMP *sm2z256;
        EC_PRE_COMP *ec;
    } pre_comp;
};

#define SETPRECOMP(g, type, pre) \
    g->pre_comp_type = PCT_##type, g->pre_comp.type = pre
#define HAVEPRECOMP(g, type) \
    g->pre_comp_type == PCT_##type && g->pre_comp.type != NULL

struct ec_key_st {
    const EC_KEY_METHOD *meth;
    ENGINE *engine;
    int version;
    EC_GROUP *group;
    EC_POINT *pub_key;
    BIGNUM *priv_key;
    unsigned int enc_flag;
    point_conversion_form_t conv_form;
    int references;
    int flags;
    CRYPTO_EX_DATA ex_data;
    CRYPTO_RWLOCK *lock;
};

struct ec_point_st {
    const EC_METHOD *meth;
    /*
     * All members except 'meth' are handled by the method functions, even if
     * they appear generic
     */
    BIGNUM *X;
    BIGNUM *Y;
    BIGNUM *Z;                  /* Jacobian projective coordinates: * (X, Y,
                                 * Z) represents (X/Z^2, Y/Z^3) if Z != 0 */
    int Z_is_one;               /* enable optimized point arithmetics for
                                 * special case */
};

NISTP224_PRE_COMP *EC_nistp224_pre_comp_dup(NISTP224_PRE_COMP *);
NISTP256_PRE_COMP *EC_nistp256_pre_comp_dup(NISTP256_PRE_COMP *);
NISTP521_PRE_COMP *EC_nistp521_pre_comp_dup(NISTP521_PRE_COMP *);
NISTZ256_PRE_COMP *EC_nistz256_pre_comp_dup(NISTZ256_PRE_COMP *);
SM2P256_PRE_COMP *EC_sm2p256_pre_comp_dup(SM2P256_PRE_COMP *);
SM2Z256_PRE_COMP *EC_sm2z256_pre_comp_dup(SM2Z256_PRE_COMP *);
EC_PRE_COMP *EC_ec_pre_comp_dup(EC_PRE_COMP *);

void EC_pre_comp_free(EC_GROUP *group);
void EC_nistp224_pre_comp_free(NISTP224_PRE_COMP *);
void EC_nistp256_pre_comp_free(NISTP256_PRE_COMP *);
void EC_nistp521_pre_comp_free(NISTP521_PRE_COMP *);
void EC_nistz256_pre_comp_free(NISTZ256_PRE_COMP *);
void EC_sm2p256_pre_comp_free(SM2P256_PRE_COMP *);
void EC_sm2z256_pre_comp_free(SM2Z256_PRE_COMP *);
void EC_ec_pre_comp_free(EC_PRE_COMP *);

/*
 * method functions in ec_mult.c (ec_lib.c uses these as defaults if
 * group->method->mul is 0)
 */
int ec_wNAF_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *scalar,
                size_t num, const EC_POINT *points[], const BIGNUM *scalars[],
                BN_CTX *);
int ec_wNAF_precompute_mult(EC_GROUP *group, BN_CTX *);
int ec_wNAF_have_precompute_mult(const EC_GROUP *group);

/* method functions in ecp_smpl.c */
int ec_GFp_simple_group_init(EC_GROUP *);
void ec_GFp_simple_group_finish(EC_GROUP *);
void ec_GFp_simple_group_clear_finish(EC_GROUP *);
int ec_GFp_simple_group_copy(EC_GROUP *, const EC_GROUP *);
int ec_GFp_simple_group_set_curve(EC_GROUP *, const BIGNUM *p,
                                  const BIGNUM *a, const BIGNUM *b, BN_CTX *);
int ec_GFp_simple_group_get_curve(const EC_GROUP *, BIGNUM *p, BIGNUM *a,
                                  BIGNUM *b, BN_CTX *);
int ec_GFp_simple_group_get_degree(const EC_GROUP *);
int ec_GFp_simple_group_check_discriminant(const EC_GROUP *, BN_CTX *);
int ec_GFp_simple_point_init(EC_POINT *);
void ec_GFp_simple_point_finish(EC_POINT *);
void ec_GFp_simple_point_clear_finish(EC_POINT *);
int ec_GFp_simple_point_copy(EC_POINT *, const EC_POINT *);
int ec_GFp_simple_point_set_to_infinity(const EC_GROUP *, EC_POINT *);
int ec_GFp_simple_set_Jprojective_coordinates_GFp(const EC_GROUP *,
                                                  EC_POINT *, const BIGNUM *x,
                                                  const BIGNUM *y,
                                                  const BIGNUM *z, BN_CTX *);
int ec_GFp_simple_get_Jprojective_coordinates_GFp(const EC_GROUP *,
                                                  const EC_POINT *, BIGNUM *x,
                                                  BIGNUM *y, BIGNUM *z,
                                                  BN_CTX *);
int ec_GFp_simple_point_set_affine_coordinates(const EC_GROUP *, EC_POINT *,
                                               const BIGNUM *x,
                                               const BIGNUM *y, BN_CTX *);
int ec_GFp_simple_point_get_affine_coordinates(const EC_GROUP *,
                                               const EC_POINT *, BIGNUM *x,
                                               BIGNUM *y, BN_CTX *);
int ec_GFp_simple_set_compressed_coordinates(const EC_GROUP *, EC_POINT *,
                                             const BIGNUM *x, int y_bit,
                                             BN_CTX *);
size_t ec_GFp_simple_point2oct(const EC_GROUP *, const EC_POINT *,
                               point_conversion_form_t form,
                               unsigned char *buf, size_t len, BN_CTX *);
int ec_GFp_simple_oct2point(const EC_GROUP *, EC_POINT *,
                            const unsigned char *buf, size_t len, BN_CTX *);
int ec_GFp_simple_add(const EC_GROUP *, EC_POINT *r, const EC_POINT *a,
                      const EC_POINT *b, BN_CTX *);
int ec_GFp_simple_dbl(const EC_GROUP *, EC_POINT *r, const EC_POINT *a,
                      BN_CTX *);
int ec_GFp_simple_invert(const EC_GROUP *, EC_POINT *, BN_CTX *);
int ec_GFp_simple_is_at_infinity(const EC_GROUP *, const EC_POINT *);
int ec_GFp_simple_is_on_curve(const EC_GROUP *, const EC_POINT *, BN_CTX *);
int ec_GFp_simple_cmp(const EC_GROUP *, const EC_POINT *a, const EC_POINT *b,
                      BN_CTX *);
int ec_GFp_simple_make_affine(const EC_GROUP *, EC_POINT *, BN_CTX *);
int ec_GFp_simple_points_make_affine(const EC_GROUP *, size_t num,
                                     EC_POINT *[], BN_CTX *);
int ec_GFp_simple_field_mul(const EC_GROUP *, BIGNUM *r, const BIGNUM *a,
                            const BIGNUM *b, BN_CTX *);
int ec_GFp_simple_field_sqr(const EC_GROUP *, BIGNUM *r, const BIGNUM *a,
                            BN_CTX *);

/* method functions in ecp_mont.c */
int ec_GFp_mont_group_init(EC_GROUP *);
int ec_GFp_mont_group_set_curve(EC_GROUP *, const BIGNUM *p, const BIGNUM *a,
                                const BIGNUM *b, BN_CTX *);
void ec_GFp_mont_group_finish(EC_GROUP *);
void ec_GFp_mont_group_clear_finish(EC_GROUP *);
int ec_GFp_mont_group_copy(EC_GROUP *, const EC_GROUP *);
int ec_GFp_mont_field_mul(const EC_GROUP *, BIGNUM *r, const BIGNUM *a,
                          const BIGNUM *b, BN_CTX *);
int ec_GFp_mont_field_sqr(const EC_GROUP *, BIGNUM *r, const BIGNUM *a,
                          BN_CTX *);
int ec_GFp_mont_field_encode(const EC_GROUP *, BIGNUM *r, const BIGNUM *a,
                             BN_CTX *);
int ec_GFp_mont_field_decode(const EC_GROUP *, BIGNUM *r, const BIGNUM *a,
                             BN_CTX *);
int ec_GFp_mont_field_set_to_one(const EC_GROUP *, BIGNUM *r, BN_CTX *);

/* method functions in ecp_nist.c */
int ec_GFp_nist_group_copy(EC_GROUP *dest, const EC_GROUP *src);
int ec_GFp_nist_group_set_curve(EC_GROUP *, const BIGNUM *p, const BIGNUM *a,
                                const BIGNUM *b, BN_CTX *);
int ec_GFp_nist_field_mul(const EC_GROUP *, BIGNUM *r, const BIGNUM *a,
                          const BIGNUM *b, BN_CTX *);
int ec_GFp_nist_field_sqr(const EC_GROUP *, BIGNUM *r, const BIGNUM *a,
                          BN_CTX *);

/* method functions in ec2_smpl.c */
int ec_GF2m_simple_group_init(EC_GROUP *);
void ec_GF2m_simple_group_finish(EC_GROUP *);
void ec_GF2m_simple_group_clear_finish(EC_GROUP *);
int ec_GF2m_simple_group_copy(EC_GROUP *, const EC_GROUP *);
int ec_GF2m_simple_group_set_curve(EC_GROUP *, const BIGNUM *p,
                                   const BIGNUM *a, const BIGNUM *b,
                                   BN_CTX *);
int ec_GF2m_simple_group_get_curve(const EC_GROUP *, BIGNUM *p, BIGNUM *a,
                                   BIGNUM *b, BN_CTX *);
int ec_GF2m_simple_group_get_degree(const EC_GROUP *);
int ec_GF2m_simple_group_check_discriminant(const EC_GROUP *, BN_CTX *);
int ec_GF2m_simple_point_init(EC_POINT *);
void ec_GF2m_simple_point_finish(EC_POINT *);
void ec_GF2m_simple_point_clear_finish(EC_POINT *);
int ec_GF2m_simple_point_copy(EC_POINT *, const EC_POINT *);
int ec_GF2m_simple_point_set_to_infinity(const EC_GROUP *, EC_POINT *);
int ec_GF2m_simple_point_set_affine_coordinates(const EC_GROUP *, EC_POINT *,
                                                const BIGNUM *x,
                                                const BIGNUM *y, BN_CTX *);
int ec_GF2m_simple_point_get_affine_coordinates(const EC_GROUP *,
                                                const EC_POINT *, BIGNUM *x,
                                                BIGNUM *y, BN_CTX *);
int ec_GF2m_simple_set_compressed_coordinates(const EC_GROUP *, EC_POINT *,
                                              const BIGNUM *x, int y_bit,
                                              BN_CTX *);
size_t ec_GF2m_simple_point2oct(const EC_GROUP *, const EC_POINT *,
                                point_conversion_form_t form,
                                unsigned char *buf, size_t len, BN_CTX *);
int ec_GF2m_simple_oct2point(const EC_GROUP *, EC_POINT *,
                             const unsigned char *buf, size_t len, BN_CTX *);
int ec_GF2m_simple_add(const EC_GROUP *, EC_POINT *r, const EC_POINT *a,
                       const EC_POINT *b, BN_CTX *);
int ec_GF2m_simple_dbl(const EC_GROUP *, EC_POINT *r, const EC_POINT *a,
                       BN_CTX *);
int ec_GF2m_simple_invert(const EC_GROUP *, EC_POINT *, BN_CTX *);
int ec_GF2m_simple_is_at_infinity(const EC_GROUP *, const EC_POINT *);
int ec_GF2m_simple_is_on_curve(const EC_GROUP *, const EC_POINT *, BN_CTX *);
int ec_GF2m_simple_cmp(const EC_GROUP *, const EC_POINT *a, const EC_POINT *b,
                       BN_CTX *);
int ec_GF2m_simple_make_affine(const EC_GROUP *, EC_POINT *, BN_CTX *);
int ec_GF2m_simple_points_make_affine(const EC_GROUP *, size_t num,
                                      EC_POINT *[], BN_CTX *);
int ec_GF2m_simple_field_mul(const EC_GROUP *, BIGNUM *r, const BIGNUM *a,
                             const BIGNUM *b, BN_CTX *);
int ec_GF2m_simple_field_sqr(const EC_GROUP *, BIGNUM *r, const BIGNUM *a,
                             BN_CTX *);
int ec_GF2m_simple_field_div(const EC_GROUP *, BIGNUM *r, const BIGNUM *a,
                             const BIGNUM *b, BN_CTX *);

/* method functions in ec2_mult.c */
int ec_GF2m_simple_mul(const EC_GROUP *group, EC_POINT *r,
                       const BIGNUM *scalar, size_t num,
                       const EC_POINT *points[], const BIGNUM *scalars[],
                       BN_CTX *);
int ec_GF2m_precompute_mult(EC_GROUP *group, BN_CTX *ctx);
int ec_GF2m_have_precompute_mult(const EC_GROUP *group);

#ifndef OPENSSL_NO_EC_NISTP_64_GCC_128
/* method functions in ecp_nistp224.c */
int ec_GFp_nistp224_group_init(EC_GROUP *group);
int ec_GFp_nistp224_group_set_curve(EC_GROUP *group, const BIGNUM *p,
                                    const BIGNUM *a, const BIGNUM *n,
                                    BN_CTX *);
int ec_GFp_nistp224_point_get_affine_coordinates(const EC_GROUP *group,
                                                 const EC_POINT *point,
                                                 BIGNUM *x, BIGNUM *y,
                                                 BN_CTX *ctx);
int ec_GFp_nistp224_mul(const EC_GROUP *group, EC_POINT *r,
                        const BIGNUM *scalar, size_t num,
                        const EC_POINT *points[], const BIGNUM *scalars[],
                        BN_CTX *);
int ec_GFp_nistp224_points_mul(const EC_GROUP *group, EC_POINT *r,
                               const BIGNUM *scalar, size_t num,
                               const EC_POINT *points[],
                               const BIGNUM *scalars[], BN_CTX *ctx);
int ec_GFp_nistp224_precompute_mult(EC_GROUP *group, BN_CTX *ctx);
int ec_GFp_nistp224_have_precompute_mult(const EC_GROUP *group);

/* method functions in ecp_nistp256.c */
int ec_GFp_nistp256_group_init(EC_GROUP *group);
int ec_GFp_nistp256_group_set_curve(EC_GROUP *group, const BIGNUM *p,
                                    const BIGNUM *a, const BIGNUM *n,
                                    BN_CTX *);
int ec_GFp_nistp256_point_get_affine_coordinates(const EC_GROUP *group,
                                                 const EC_POINT *point,
                                                 BIGNUM *x, BIGNUM *y,
                                                 BN_CTX *ctx);
int ec_GFp_nistp256_mul(const EC_GROUP *group, EC_POINT *r,
                        const BIGNUM *scalar, size_t num,
                        const EC_POINT *points[], const BIGNUM *scalars[],
                        BN_CTX *);
int ec_GFp_nistp256_points_mul(const EC_GROUP *group, EC_POINT *r,
                               const BIGNUM *scalar, size_t num,
                               const EC_POINT *points[],
                               const BIGNUM *scalars[], BN_CTX *ctx);
int ec_GFp_nistp256_precompute_mult(EC_GROUP *group, BN_CTX *ctx);
int ec_GFp_nistp256_have_precompute_mult(const EC_GROUP *group);

/* method functions in ecp_nistp521.c */
int ec_GFp_nistp521_group_init(EC_GROUP *group);
int ec_GFp_nistp521_group_set_curve(EC_GROUP *group, const BIGNUM *p,
                                    const BIGNUM *a, const BIGNUM *n,
                                    BN_CTX *);
int ec_GFp_nistp521_point_get_affine_coordinates(const EC_GROUP *group,
                                                 const EC_POINT *point,
                                                 BIGNUM *x, BIGNUM *y,
                                                 BN_CTX *ctx);
int ec_GFp_nistp521_mul(const EC_GROUP *group, EC_POINT *r,
                        const BIGNUM *scalar, size_t num,
                        const EC_POINT *points[], const BIGNUM *scalars[],
                        BN_CTX *);
int ec_GFp_nistp521_points_mul(const EC_GROUP *group, EC_POINT *r,
                               const BIGNUM *scalar, size_t num,
                               const EC_POINT *points[],
                               const BIGNUM *scalars[], BN_CTX *ctx);
int ec_GFp_nistp521_precompute_mult(EC_GROUP *group, BN_CTX *ctx);
int ec_GFp_nistp521_have_precompute_mult(const EC_GROUP *group);

/* method functions in ecp_sm2p256.c */
int ec_GFp_sm2p256_group_init(EC_GROUP *group);
int ec_GFp_sm2p256_group_set_curve(EC_GROUP *group, const BIGNUM *p,
                                   const BIGNUM *a, const BIGNUM *n,
                                   BN_CTX *);
int ec_GFp_sm2p256_point_get_affine_coordinates(const EC_GROUP *group,
                                                const EC_POINT *point,
                                                BIGNUM *x, BIGNUM *y,
                                                BN_CTX *ctx);
int ec_GFp_sm2p256_mul(const EC_GROUP *group, EC_POINT *r,
                       const BIGNUM *scalar, size_t num,
                       const EC_POINT *points[], const BIGNUM *scalars[],
                       BN_CTX *);
int ec_GFp_sm2p256_points_mul(const EC_GROUP *group, EC_POINT *r,
                              const BIGNUM *scalar, size_t num,
                              const EC_POINT *points[],
                              const BIGNUM *scalars[], BN_CTX *ctx);
int ec_GFp_sm2p256_precompute_mult(EC_GROUP *group, BN_CTX *ctx);
int ec_GFp_sm2p256_have_precompute_mult(const EC_GROUP *group);

/* utility functions in ecp_nistputil.c */
void ec_GFp_nistp_points_make_affine_internal(size_t num, void *point_array,
                                              size_t felem_size,
                                              void *tmp_felems,
                                              void (*felem_one) (void *out),
                                              int (*felem_is_zero) (const void
                                                                    *in),
                                              void (*felem_assign) (void *out,
                                                                    const void
                                                                    *in),
                                              void (*felem_square) (void *out,
                                                                    const void
                                                                    *in),
                                              void (*felem_mul) (void *out,
                                                                 const void
                                                                 *in1,
                                                                 const void
                                                                 *in2),
                                              void (*felem_inv) (void *out,
                                                                 const void
                                                                 *in),
                                              void (*felem_contract) (void
                                                                      *out,
                                                                      const
                                                                      void
                                                                      *in));
void ec_GFp_nistp_recode_scalar_bits(unsigned char *sign,
                                     unsigned char *digit, unsigned char in);
#endif
int ec_precompute_mont_data(EC_GROUP *);
int ec_group_simple_order_bits(const EC_GROUP *group);

#ifdef ECP_NISTZ256_ASM
/** Returns GFp methods using montgomery multiplication, with x86-64 optimized
 * P256. See http://eprint.iacr.org/2013/816.
 *  \return  EC_METHOD object
 */
const EC_METHOD *EC_GFp_nistz256_method(void);
#endif

#ifndef OPENSSL_NO_SM2
# if defined(ECP_NISTZ256_ASM) && BN_BITS2 == 64 && !defined(GMSSL_NO_TURBO)
const EC_METHOD *EC_GFp_sm2z256_method(void);
# endif
#endif

size_t ec_key_simple_priv2oct(const EC_KEY *eckey,
                              unsigned char *buf, size_t len);
int ec_key_simple_oct2priv(EC_KEY *eckey, const unsigned char *buf, size_t len);
int ec_key_simple_generate_key(EC_KEY *eckey);
int ec_key_simple_generate_public_key(EC_KEY *eckey);
int ec_key_simple_check_key(const EC_KEY *eckey);

/* EC_METHOD definitions */

struct ec_key_method_st {
    const char *name;
    int32_t flags;
    int (*init)(EC_KEY *key);
    void (*finish)(EC_KEY *key);
    int (*copy)(EC_KEY *dest, const EC_KEY *src);
    int (*set_group)(EC_KEY *key, const EC_GROUP *grp);
    int (*set_private)(EC_KEY *key, const BIGNUM *priv_key);
    int (*set_public)(EC_KEY *key, const EC_POINT *pub_key);
    int (*keygen)(EC_KEY *key);
    int (*compute_key)(unsigned char **pout, size_t *poutlen,
                       const EC_POINT *pub_key, const EC_KEY *ecdh);
    int (*sign)(int type, const unsigned char *dgst, int dlen, unsigned char
                *sig, unsigned int *siglen, const BIGNUM *kinv,
                const BIGNUM *r, EC_KEY *eckey);
    int (*sign_setup)(EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM **kinvp,
                      BIGNUM **rp);
    ECDSA_SIG *(*sign_sig)(const unsigned char *dgst, int dgst_len,
                           const BIGNUM *in_kinv, const BIGNUM *in_r,
                           EC_KEY *eckey);

    int (*verify)(int type, const unsigned char *dgst, int dgst_len,
                  const unsigned char *sigbuf, int sig_len, EC_KEY *eckey);
    int (*verify_sig)(const unsigned char *dgst, int dgst_len,
                      const ECDSA_SIG *sig, EC_KEY *eckey);

};

#define EC_KEY_METHOD_DYNAMIC   1

int ossl_ec_key_gen(EC_KEY *eckey);
int ossl_ecdh_compute_key(unsigned char **pout, size_t *poutlen,
                          const EC_POINT *pub_key, const EC_KEY *ecdh);
int ecdh_simple_compute_key(unsigned char **pout, size_t *poutlen,
                            const EC_POINT *pub_key, const EC_KEY *ecdh);

struct ECDSA_SIG_st {
    BIGNUM *r;
    BIGNUM *s;
};

int ossl_ecdsa_sign_setup(EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM **kinvp,
                          BIGNUM **rp);
int ossl_ecdsa_sign(int type, const unsigned char *dgst, int dlen,
                    unsigned char *sig, unsigned int *siglen,
                    const BIGNUM *kinv, const BIGNUM *r, EC_KEY *eckey);
ECDSA_SIG *ossl_ecdsa_sign_sig(const unsigned char *dgst, int dgst_len,
                               const BIGNUM *in_kinv, const BIGNUM *in_r,
                               EC_KEY *eckey);
int ossl_ecdsa_verify(int type, const unsigned char *dgst, int dgst_len,
                      const unsigned char *sigbuf, int sig_len, EC_KEY *eckey);
int ossl_ecdsa_verify_sig(const unsigned char *dgst, int dgst_len,
                          const ECDSA_SIG *sig, EC_KEY *eckey);

int X25519(uint8_t out_shared_key[32], const uint8_t private_key[32],
           const uint8_t peer_public_value[32]);
void X25519_public_from_private(uint8_t out_public_value[32],
                                const uint8_t private_key[32]);


#  ifdef  __cplusplus
}
#  endif
# endif
#endif
