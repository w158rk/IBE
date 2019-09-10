#include <crypto.h>
#include <string.h>

void ibe_sk_copy(IBEPrivateKey *dest, IBEPrivateKey *src) {
    IBEPrivateKey tmp = (IBEPrivateKey)malloc(IBE_SK_LEN);
    memcpy(tmp, *src, IBE_SK_LEN);
    *dest = tmp;
}