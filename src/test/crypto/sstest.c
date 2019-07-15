#include <stdio.h>
#include <stdlib.h>
#include <crypto.h>
#include <openssl/bn.h>

#define DEBUG
#define SS_POLY_LENGTH 3
#define ERROR(s) fprintf(stderr, "[%s:%d] in [%s] %s\n", \
                        __FILE__, __LINE__, __func__, s)
SS_POLY *poly;
BIGNUM *p;

int SS_poly_rand_test() {
    if( 0 == SS_poly_rand(poly, SS_POLY_LENGTH, p)) {

        ERROR("something went wrong");
        goto end;

    }

    fprintf(stderr, "test %s:%d\n", __FILE__, __LINE__);
        
    printf("--------------------------------\n");
    printf("test SS_poly_rand : \n");
    printf("the degree : %d\n", poly->length-1);
    BIGNUM **coeff = poly->coeff;
    
    int i=0;
    for (i=0; i<poly->length; ++i) {
        printf("coeff[%d] : ", i);
        BN_print_fp(stdout, coeff[i]); 
        printf("\n");
    }

    return 1;
end:
    return 0;

}

int SS_poly_apply_test() {
        
    BIGNUM *x[3] = { NULL };
    BIGNUM *y[3] = { NULL };
    BIGNUM *ref[3] = { NULL };
    BIGNUM *temp = BN_new();

    BN_CTX *ctx = BN_CTX_new();
    /* set x as 1, 0, -1 */
    int i=0;
    for (i=0; i<3; ++i) {

        x[i] = BN_new();
        y[i] = BN_new();
        ref[i] = BN_new();

    }

    BN_zero(x[0]);
    BN_one(x[1]);
    if( 0 == BN_mod_sub(x[2], x[0], x[1], p, ctx)) {
        
        ERROR("sub error");
        goto end;

    }

    BIGNUM **coeff = poly -> coeff;
    
    BN_copy(ref[0], coeff[0]);

    /*ref[1] = coeff2 + coeff1 + coeff0 */
    if(0 == BN_mod_add(temp, coeff[0], coeff[1], p, ctx)) {

        ERROR("add error");
        goto end;

    }
    if(0 == BN_mod_add(ref[1], coeff[2], temp, p, ctx)) {

        ERROR("add error");
        goto end;

    }

    /*ref[2] = coeff2 - coeff1 + coeff0 */
    if(0 == BN_mod_sub(temp, coeff[2], coeff[1], p, ctx)) {

        ERROR("sub error");
        goto end;

    }
    if(0 == BN_mod_add(ref[2], coeff[0], temp, p, ctx)) {

        ERROR("add error");
        goto end;

    }

    SS_poly_apply(y[0], poly, x[0], p);
    SS_poly_apply(y[1], poly, x[1], p);
    SS_poly_apply(y[2], poly, x[2], p);

    for (i=0; i<3; ++i) {

        if( 0!= BN_cmp(y[i], ref[i])) {
            
            fprintf(stderr, "y[%d] = ", i);
            BN_print_fp(stderr, y[i]);
            fprintf(stderr, "\n");
            fprintf(stderr, "ref[%d] = ", i);
            BN_print_fp(stderr, ref[i]);
            fprintf(stderr, "\n");
            goto end;

        }

    }

    for (i=0; i<3; i++) {

        BN_free(x[i]);
        BN_free(y[i]);
        BN_free(ref[i]);

    }
    BN_free(temp);
    BN_CTX_free(ctx);
    return 1;

end:
    for (i=0; i<3; ++i) {

        
        BN_free(x[i]);
        BN_free(y[i]);
        BN_free(ref[i]);

    }
    BN_free(temp);
    BN_CTX_free(ctx);
    return 0;

}

int SS_lagrange_value_test() {

    printf("---------------------SS_lagrange_value-------------------\n");

    BIGNUM *x_list[3] = { NULL };
    BIGNUM *x = BN_new();
    BIGNUM *value = BN_new();

    BN_CTX *ctx = BN_CTX_new();

    int j = 0;
    for (j=0; j<3; ++j) {
        x_list[j] = BN_new();
    }

    /* the three numbers are 0, 1, -1 */
    BN_zero(x_list[0]);
    BN_one(x_list[1]);
    if(0 == BN_mod_sub(x_list[2], x_list[0], x_list[1], p, ctx)) {

        ERROR("sub went wrong");
        goto end;

    }

    /* the test number is 2 */
    if(0 == BN_mod_lshift1(x, x_list[1], p, ctx)) {

        ERROR("lshift went wrong");
        goto end;

    }

    for(j=0; j<3; j++) {
        printf(" x[%d] : ", j);
        BN_print_fp(stdout, x_list[j]);
        printf("\n");
    }

    printf("x : ");
    BN_print_fp(stdout, x);
    printf("\n");
    /* get the lagrange values */
    if(0 == SS_lagrange_value(value, x_list, 3, 0, x, p)) {

            ERROR("lagrange function went wrong");
            goto end;

    }
    BN_print_fp(stdout, value);
    printf("\n");

    if(0 == SS_lagrange_value(value, x_list, 3, 1, x, p)) {

            ERROR("lagrange function went wrong");
            goto end;

    }
    BN_print_fp(stdout, value);
    printf("\n");

    if(0 == SS_lagrange_value(value, x_list, 3, 2, x, p)) {

            ERROR("lagrange function went wrong");
            goto end;

    }
    BN_print_fp(stdout, value);
    printf("\n");

    BN_CTX_free(ctx);
    for (j=0; j<3; ++j) {

        BN_free(x_list[j]);

    }
    BN_free(value);
    BN_free(x);
    return 1;

end:
    BN_CTX_free(ctx);
    for (j=0; j<3; ++j) {

        BN_free(x_list[j]);

    }
    BN_free(value);
    BN_free(x);
    return 0;


}

int ss_num_test() {

    if(0 == SS_poly_rand_test()) {

        ERROR("something went wrong in the [ss_poly_rand_test]\n");
        goto end;

    }

    if(0 == SS_poly_apply_test()) {
     
        ERROR("something went wrong in the [ss_poly_apply_test]\n");
        goto end;

    }

    if(0 == SS_lagrange_value_test()) {
     
        ERROR("something went wrong in the [ss_lagrange_value_test]\n");
        goto end;

    }


    return 1;

end:
    return 0;
}

int ss_point_test() {



}

int main(int argc, char *argv[]) {

    /* initialize the global variables */
    p = SS_get_p();
    BN_print_fp(stdout, p);
    printf("\n");
    poly = SS_POLY_new();
 
    if(0 == ss_num_test()) {

        ERROR("something went wrong in the [ss_num_test]\n");
        goto end;

    }
    if(0 == ss_point_test()) {

        ERROR("somthing went wrong in the [ss_point_test]\n");
        goto end;

    }

    printf("[ss_test] test pass\n");
    return 0;

end:
    printf("[ss_test] something went wrong\n");
    return -1;

}
