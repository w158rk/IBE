#include <sys.h>

#include<openssl/sm9.h>
#include <openssl/bio.h>

int sys_setup(const char* mpk_filename, const char* msk_filename)
{
   	SM9PublicParameters *mpk = NULL;
	SM9MasterSecret *msk = NULL;

   	if (!SM9_setup(NID_sm9bn256v1, NID_sm9encrypt, NID_sm9hash1_with_sm3, &mpk, &msk)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}


    /* output mpk  */
    FILE *mpk_fp = fopen(mpk_filename, "wb");

    if (!i2d_SM9PublicParameters_fp(mpk_fp, mpk)){
		ERR_print_errors_fp(stderr);
        fclose(mpk_fp);
        goto end;
    }
    fclose(mpk_fp);

    /* output msk  */
    FILE *msk_fp = fopen(msk_filename, "wb");
    if (!i2d_SM9MasterSecret_fp(msk_fp, msk)) {
		ERR_print_errors_fp(stderr);
        fclose(msk_fp);
        goto end;
    }
    fclose(msk_fp);

    return 1;

end:
	SM9PublicParameters_free(mpk);
	SM9MasterSecret_free(msk);
    return 0;

}