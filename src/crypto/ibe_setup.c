
#include <crypto.h>
#include <openssl/sm9.h>
#include <openssl/bio.h>
#include <utils.h>

int ibe_setup(
    char *mpk_file,
    char *msk_file,
    char *mpk_len_file,
    char *msk_len_file
)
{
#ifdef DEBUG
    ERROR("enter ibe setup");
#endif

    int ret = 0;
   	SM9PublicParameters *mpk = NULL;
	SM9MasterSecret *msk = NULL;

   	if (!SM9_setup(NID_sm9bn256v1, NID_sm9encrypt, NID_sm9hash1_with_sm3, &mpk, &msk)) {
        ERROR(" sm9 set up failed");
        goto end;
	}

    /* output mpk  */
    FILE *mpk_fp = fopen(mpk_file, "wb+");
    
    if (!i2d_SM9PublicParameters_fp(mpk_fp, mpk)){
        ERROR("output mpk to file failed");
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
    if (!i2d_SM9MasterSecret_fp(msk_fp, msk)) {
        ERROR("output msk to file failed");
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
#ifdef DEBUG
    ERROR("exit ibe setup");
#endif
end:
	SM9PublicParameters_free(mpk);
	SM9MasterSecret_free(msk);
    return ret;

}