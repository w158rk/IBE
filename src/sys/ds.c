#include <ds.h>
#include <utils.h>
#include <string.h>

int ID_equal(ID *a, ID *b)
{
    if(!a || !b)
    {
        ERROR("At least one of the ID compared is NULL");
        return 0;
    }
    if(a->length != b->length)
    {
        return 0;
    }
    return !strncmp(a->id, b->id, a->length);
}