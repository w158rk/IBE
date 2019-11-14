#include <utils.h>

void set_int(char *ptr, int val)
{
    *(int *)ptr = val;
}

void get_int(char *ptr, int *val)
{
    *val = *(int *)ptr;
}