#ifndef IBE_ERR_H 
#define IBE_ERR_H 



/* ERRORS */
#define MPK_ERROR           100
#define MSK_ERROR           200
#define SK_ERROR            300
#define ENC_ERROR           400
#define DEC_ERROR           500
#define CAL_ERROR           600
#define MEM_ERROR           700

#define LEN_ERROR               1
#define FROM_STR_ERROR          2
#define TO_STR_ERROR            3
#define OPENSSL_ERROR           4
#define POINTER_NULL_ERROR      5
#define POINTER_NOT_NULL_ERROR  6
#define POINT_ERROR             7
#define NUM_ERROR               8
#define ALLOC_ERROR             9

// #define ERROR_NAME(parent, sub) parent ## _ ## sub ## _ERROR
// #define ERROR_VALUE(parent, sub) parent ## _ ## ERROR ## sub  ## _ERROR
#define DEFINE_ERROR(parent, sub) const int \
        parent ## _ ## sub ## _ERROR = parent ## _ ## ERROR + sub  ## _ERROR;

DEFINE_ERROR(MPK, LEN)
DEFINE_ERROR(MPK, FROM_STR)
DEFINE_ERROR(MPK, TO_STR)

DEFINE_ERROR(MSK, LEN)
DEFINE_ERROR(MSK, FROM_STR)
DEFINE_ERROR(MSK, TO_STR)

DEFINE_ERROR(SK, LEN)
DEFINE_ERROR(SK, FROM_STR)
DEFINE_ERROR(SK, TO_STR)

DEFINE_ERROR(ENC, OPENSSL)
DEFINE_ERROR(DEC, OPENSSL)

DEFINE_ERROR(CAL, POINTER_NOT_NULL)

DEFINE_ERROR(MEM, ALLOC)

/* ERROR strings */

#define MPK_LEN_ERROR_STR           "the length of mpk is not 239"
#define MPK_LEN_ERROR_INT           "the length is: "
#define MPK_FROM_STR_ERROR_STR      "cannot extract mpk from string"
#define MPK_FROM_STR_ERROR_INT      "the length is: "

#define MSK_LEN_ERROR_STR           "the length of msk is not ?"
#define MSK_LEN_ERROR_INT           "the length is: "
#define MSK_FROM_STR_ERROR_STR      "the length of msk is not ?"
#define MSK_FROM_STR_ERROR_INT      "the length is: "

#define SK_LEN_ERROR_STR            "the length of sk is not ?"
#define SK_LEN_ERROR_INT            "the length is: "
#define SK_FROM_STR_ERROR_STR       "the length of sk is not ?"
#define SK_FROM_STR_ERROR_INT       "the length is: "

#define ENC_OPENSSL_ERROR_STR       "error in smx encrypt (openssl)"
#define DEC_OPENSSL_ERROR_STR       "error in smx decrypt (openssl)"

#define CAL_POINTER_NOT_NULL_ERROR_STR    "the pointer is not NULL"
#define CAL_POINTER_NULL_ERROR_STR        "the pointer is NULL"

#define MEM_ALLOC_ERROR_STR         "the location failed"


#define ERROR(err_type) fprintf(stderr, "[%s:%d]%s\n", err_type ## _STR)
#define ERROR_WITH_STR(err_type, aux) \
    fprintf(stderr, "[%s:%d]\n%s(%s)\n", err_type ## _STR, aux)
#define ERROR_WITH_INT(err_type, aux) \
    fprintf(stderr, "[%s:%d]\n%s(%s:%d)\n", err_type ## _STR, err_type ## _INT, aux)
#define ERROR_WITH_LONG(err_type, aux) \
    fprintf(stderr, "[%s:%d]\n%s(%s:%ld)\n", err_type ## _STR, err_type ## _INT, aux)

#endif