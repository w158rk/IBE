#include <config.h>
#include <comm.hpp>

#include "init_lcl.hpp"

using namespace init;

#define Error(err) get_user()->get_ui_ptr()->error(err)
#define Print(err) get_user()->get_ui_ptr()->print(err)

# ifdef DEBUG
# include <sstream>
# define Debug(err) get_user()->get_ui_ptr()->debug(err)
# endif


void Initializer::store_sP()
{
    char *mpk_filename = user_get_mpk_filename(get_user());
#ifdef DEBUG 
{
    fprintf(stderr, "filename : %s\n", mpk_filename);
}
#endif
    EC_POINT *sP = get_sP();
    ibe_ec_store_Ppub1(sP, mpk_filename);
    point_t *pPub2 = get_Ppub2();
    ibe_point_store_Ppub2(pPub2, mpk_filename);
}

void Initializer::store_sQ()
{
    EC_POINT *sQ = get_sP();
    user::User *user = get_user();
    ibe_ec_store_sk(sQ, user_get_id(user), user_get_mpk_filename(user), user_get_sk_filename(user));

}
