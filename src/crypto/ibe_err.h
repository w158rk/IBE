#ifndef IBE_ERR_H 
#define IBE_ERR_H 



/* ERRORS */
#define MPK_ERROR           100
#define MSK_ERROR           200
#define SK_ERROR            300
#define MEM_ERROR           700

#define OPENSSL_ERROR       400

#define EC_ERROR            1000
#define BN_ERROR            1100
#define POINT_ERROR         1200

#define LEN_ERROR               1
#define FROM_STR_ERROR          2
#define TO_STR_ERROR            3
#define OPENSSL_ERROR           4
#define POINTER_NULL_ERROR      5
#define POINTER_NOT_NULL_ERROR  6
#define ALLOC_ERROR             9
#define CAL_ERROR               10
#define FROM_FILE_ERROR         11
#define TO_FILE_ERROR           12
#define ENC_ERROR               13
#define DEC_ERROR               14
#define SIGN_ERROR              15
#define VERIFY_ERROR            16
#define HASH_ERROR              17
#define SET_MEMBER_ERROR        18
#define NOT_IN_GROUP_ERROR      19
#define SETUP_ERROR            20

// #define ERROR_NAME(parent, sub) parent ## _ ## sub ## _ERROR
// #define ERROR_VALUE(parent, sub) parent ## _ ## ERROR ## sub  ## _ERROR
#define DEFINE_ERROR(parent, sub, str) static const int \
        parent ## _ ## sub ## _ERROR = parent ## _ ## ERROR + sub  ## _ERROR; \
        static const char *parent ## _ ## sub ## _ERROR_STR = str;

DEFINE_ERROR(MPK, LEN, "the length of mpk is not 239")
DEFINE_ERROR(MPK, FROM_STR, "cannot extract mpk from string")
DEFINE_ERROR(MPK, TO_STR, "cannot convert mpk to str")
DEFINE_ERROR(MPK, FROM_FILE, "cannot read mpk from file")
DEFINE_ERROR(MPK, TO_FILE, "cannot write mpk to file")
DEFINE_ERROR(MPK, SET_MEMBER, "cannot set members of mpk")

DEFINE_ERROR(MSK, LEN, "the length of msk is not ?")
DEFINE_ERROR(MSK, FROM_STR, "cannot extract msk from string")
DEFINE_ERROR(MSK, TO_STR, "cannot convert msk to str")
DEFINE_ERROR(MSK, FROM_FILE, "cannot read msk from file")
DEFINE_ERROR(MSK, TO_FILE, "cannot write msk to file")

DEFINE_ERROR(SK, LEN, "the length of sk is not ?")
DEFINE_ERROR(SK, FROM_STR, "cannot extract sk from string")
DEFINE_ERROR(SK, TO_STR, "cannot convert sk to str")
DEFINE_ERROR(SK, FROM_FILE, "cannot read sk from file")
DEFINE_ERROR(SK, TO_FILE, "cannot write sk to file")
DEFINE_ERROR(SK, SET_MEMBER, "cannot set members of sk")

DEFINE_ERROR( OPENSSL, ENC, "error in smx encrypt (openssl)")
DEFINE_ERROR( OPENSSL, DEC, "error in smx decrypt (openssl)")
DEFINE_ERROR( OPENSSL, SIGN, "error in smx sign (openssl)")
DEFINE_ERROR( OPENSSL, VERIFY, "error in smx verify (openssl)")
DEFINE_ERROR( OPENSSL, HASH, "error in hash functions (openssl)")
DEFINE_ERROR( OPENSSL, SETUP, "error in setup (openssl)")

DEFINE_ERROR(MEM, ALLOC, "the allocation failed")
DEFINE_ERROR(MEM, POINTER_NOT_NULL, "the pointer is not NULL")
DEFINE_ERROR(MEM, POINTER_NULL, "the pointer is NULL")

DEFINE_ERROR(EC, CAL, "error in ec pointer calculation")
DEFINE_ERROR(EC, FROM_STR, "cannot extract ec point from the string")
DEFINE_ERROR(EC, TO_STR, "cannot convert the ec point to string")

DEFINE_ERROR(POINT, CAL, "error in pointer calculation")
DEFINE_ERROR(POINT, TO_STR, "cannot convert the point to string")
DEFINE_ERROR(POINT, FROM_STR, "cannot extract the point from string")
DEFINE_ERROR(POINT, NOT_IN_GROUP, "the point is not in G2")

/* ERROR strings */

// #define MPK_LEN_ERROR_STR           "the length of mpk is not 239"
#define MPK_LEN_ERROR_INT           "the length is: "
// #define MPK_FROM_STR_ERROR_STR      "cannot extract mpk from string"
#define MPK_FROM_STR_ERROR_INT      "the length is: "

// #define MSK_LEN_ERROR_STR           "the length of msk is not ?"
#define MSK_LEN_ERROR_INT           "the length is: "
// #define MSK_FROM_STR_ERROR_STR      "the length of msk is not ?"
#define MSK_FROM_STR_ERROR_INT      "the length is: "

// #define SK_LEN_ERROR_STR            "the length of sk is not ?"
#define SK_LEN_ERROR_INT            "the length is: "
// #define SK_FROM_STR_ERROR_STR       "the length of sk is not ?"
#define SK_FROM_STR_ERROR_INT       "the length is: "

// #define ENC_OPENSSL_ERROR_STR       "error in smx encrypt (openssl)"
// #define DEC_OPENSSL_ERROR_STR       "error in smx decrypt (openssl)"
// #define SIGN_OPENSSL_ERROR_STR      "error in smx sign (openssl)"
// #define VERIFY_OPENSSL_ERROR_STR    "error in smx verify (openssl)"

// #define EC_POINTER_NOT_NULL_ERROR_STR    "the pointer is not NULL"
#define EC_POINTER_NULL_ERROR_STR        "the pointer is NULL"
// #define EC_CAL_ERROR_STR                 "error in ec pointer calculation"

// #define MEM_ALLOC_ERROR_STR         "the location failed"


#define ERROR(err_type) fprintf(stderr, "[%s:%d]%s\n", __FILE__, __LINE__, err_type ## _STR)
#define ERROR_WITH_STR(err_type, aux) \
    fprintf(stderr, "[%s:%d]\n%s(%s)\n", __FILE__, __LINE__, err_type ## _STR, aux)
#define ERROR_WITH_INT(err_type, aux) \
    fprintf(stderr, "[%s:%d]\n%s(%s:%d)\n", __FILE__, __LINE__, err_type ## _STR, err_type ## _INT, aux)
#define ERROR_WITH_LONG(err_type, aux) \
    fprintf(stderr, "[%s:%d]\n%s(%s:%ld)\n", __FILE__, __LINE__, err_type ## _STR, err_type ## _INT, aux)

#endif