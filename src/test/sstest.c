#include <ss.h>

int test_1()
{
    SS_POLY *poly = SS_POLY_new();
    int len = 3;
    poly->length = len;
    poly->coeff = (BIGNUM **)malloc(len * sizeof(BIGNUM *));
    SS_poly_rand_smx(poly, len);

    char *buf = (char *)malloc(65 * len);
    SS_poly2str(buf, poly);
    char *p = buf;

    int i;
    for(i=0; i<len; i++)
    {
        printf("%s\n", p);
        p += 65;
    }

    SS_POLY *new_poly = SS_str2poly(buf, len);
    if(new_poly)
    {
        for(i=0; i<len; i++)
        {
            BN_print_fp(stdout, new_poly->coeff[i]);
            printf("\n");
        }
    }
    else 
    {
        printf("return NULL\n");
    }

}

int test_2()
{
    int len = 3;
    char *poly_str = SS_new_rand_poly_py(len);
    
    char bn[65] = "1";
    char *val = SS_poly_apply_py(poly_str, len, bn);

    int i;
    char *p;
    for(i=0, p=poly_str; i<len; i++)
    {
        printf("%s\n", p);
        p += 65;
    }

    printf("%s\n", val);
}

int main()
{
    test_2();
}