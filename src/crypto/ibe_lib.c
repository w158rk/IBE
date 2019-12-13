# include "smx_lcl.h"
# include "ibe_err.h"

#include <crypto.h>
#include <utils.h>
#include <config.h>
#include <string.h>

void ibe_sk_copy(IBEPrivateKey *dest, IBEPrivateKey *src, long sk_len) {
    IBEPrivateKey tmp = (IBEPrivateKey)malloc(sk_len);
    memcpy(tmp, *src, sk_len);
    *dest = tmp;
}

char *ibe_malloc_char(size_t size)
{

    char *ret = (char *)malloc(size+1);
    memset(ret, 0, size+1);
    return ret;

}

void ibe_free_char(char *buf)
{
	if(!buf) return;
	free(buf);
}

#define DEFINE_FILE_TYPE(type, prefix, len_of_prefix)	\
const static char* FILE_PREFIX_ ## type = prefix;			\
const static int FILE_PREFIX_LEN_ ## type = len_of_prefix;

DEFINE_FILE_TYPE(SK, "sk_", 3)
DEFINE_FILE_TYPE(SK_LEN, "sk-len_", 7)
DEFINE_FILE_TYPE(MPK, "mpk-", 4)

int ibe_gen_filename(char **to, ID *id, const char*prefix, int len_of_prefix)
{

	if(*to!=NULL)
	{
		ERROR(MEM_POINTER_NOT_NULL_ERROR);
		return 0;
	}

	int ret = 0;

	int filename_len = id->length + len_of_prefix + 6;    
    char *filename = (char *)malloc(filename_len); 
	memcpy(filename, prefix, len_of_prefix); 
    memcpy(filename+len_of_prefix, (id->id), (id->length));
    filename[filename_len-6] = '.'; 
    filename[filename_len-5] = 'c'; 
    filename[filename_len-4] = 'o'; 
    filename[filename_len-3] = 'n'; 
    filename[filename_len-2] = 'f';
    filename[filename_len-1] = '\0';

	*to = filename;
	ret = 1;
	return ret;

}

int ibe_gen_sk_filename(char **to, ID *id)
{

	return ibe_gen_filename(to, id, FILE_PREFIX_SK, FILE_PREFIX_LEN_SK);

}

int ibe_gen_sk_len_filename(char **to, ID *id)
{

	return ibe_gen_filename(to, id, FILE_PREFIX_SK_LEN, FILE_PREFIX_LEN_SK_LEN);

}

int ibe_gen_mpk_filename(char **to, ID *id)
{

	return ibe_gen_filename(to, id, FILE_PREFIX_MPK, FILE_PREFIX_LEN_MPK);

}

void ibe_free_filename(char *filename)
{
	free(filename);
}