#include <stdio.h>
#include <string.h>
#include <stdlib.h>

# include <crypto.h>
# include <openssl/evp.h>
# include <openssl/sm3.h>


char *hash_sm3_py(char *m, long m_len)
{

	int err = 0;
	char *ret = NULL;
	unsigned char dgst[EVP_MAX_MD_SIZE];
	unsigned int dgstlen;

    if (!EVP_Digest(m, m_len, dgst, &dgstlen, EVP_sm3(), NULL)) {
        return NULL;
    }

    ret = (char *)malloc(EVP_MAX_MD_SIZE);
    memcpy(ret, dgst, dgstlen);
    return ret;

}
