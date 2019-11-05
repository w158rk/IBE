#include <crypto.h>
#include <string.h>

void ibe_sk_copy(IBEPrivateKey *dest, IBEPrivateKey *src, long sk_len) {
    IBEPrivateKey tmp = (IBEPrivateKey)malloc(sk_len);
    memcpy(tmp, *src, sk_len);
    *dest = tmp;
}