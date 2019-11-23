
#include <crypto.h>
#include "smx_lcl.h"
#include "ibe_err.h"
#include <openssl/bio.h>

int ibe_setup(
    char *mpk_file,
    char *msk_file,
    char *mpk_len_file,
    char *msk_len_file
)
{

    int ret = 0;
   	SMXPublicParameters *mpk = NULL;
	SMXMasterSecret *msk = NULL;

   	if (!SMX_setup(NID_sm9bn256v1, NID_sm9encrypt, NID_sm9hash1_with_sm3, &mpk, &msk)) {
        ERROR(OPENSSL_SETUP_ERROR);
        goto end;
	}

    /* output mpk  */
    FILE *mpk_fp = fopen(mpk_file, "wb+");
    
    if (!i2d_SMXPublicParameters_fp(mpk_fp, mpk)){
        ERROR(MPK_TO_FILE_ERROR);
        fclose(mpk_fp);
        goto end;
    }

    /* from length the file determine the length of the mpk */
    fseek(mpk_fp, 0, SEEK_END);
    long mpk_len = ftell(mpk_fp);
    fclose(mpk_fp);

    /* open the mpk len file and output*/
    FILE *mpk_len_fp = fopen(mpk_len_file, "wb");
    fwrite(&mpk_len, sizeof(mpk_len), 1, mpk_len_fp);
    fclose(mpk_len_fp);

    /* output msk  */
    FILE *msk_fp = fopen(msk_file, "wb");
    if (!i2d_SMXMasterSecret_fp(msk_fp, msk)) {
        ERROR(MSK_TO_FILE_ERROR);
        fclose(mpk_fp);
        goto end;
    }

    fseek(msk_fp, 0, SEEK_END);
    long msk_len = ftell(msk_fp);
    fclose(msk_fp);

    /* open the msk len file and output*/
    FILE *msk_len_fp = fopen(msk_len_file, "wb");
    fwrite(&msk_len, sizeof(msk_len), 1, msk_len_fp);
    fclose(msk_len_fp);

    ret = 1;
end:
	SMXPublicParameters_free(mpk);
	SMXMasterSecret_free(msk);
    return ret;

}