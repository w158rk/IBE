#include <ss.h>

int main()
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
