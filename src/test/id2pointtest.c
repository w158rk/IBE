#include <crypto.h>
#include <openssl/ec.h>

#define TEST_ID "Server"
#define TEST_ID_LEN 6
#define MPK_FILE "mpk.conf"

int main() 
{
    EC_POINT *point = NULL;
    int ret = ibe_id2point_init(
        &point,
        TEST_ID, 
        TEST_ID_LEN,
        MPK_FILE
    );

    printf("test : %d\n", ret);
}