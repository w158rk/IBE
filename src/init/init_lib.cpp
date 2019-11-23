#include <config.h>
#include <init.hpp>
#include <comm.hpp>

using namespace init;

#define Error(err) get_user()->get_ui_ptr()->error(err)
#define Print(err) get_user()->get_ui_ptr()->print(err)

# ifdef DEBUG
# include <sstream>
# define Debug(err) get_user()->get_ui_ptr()->debug(err)
# endif


void Initializer::store_sP()
{
    EC_POINT *sP = get_sP();
    ibe_ec_store_Ppub1(sP, get_user()->get_mpk_filename());
    point_t *pPub2 = get_Ppub2();
    ibe_point_store_Ppub2(pPub2, get_user()->get_mpk_filename());
}

void Initializer::store_sQ()
{
    EC_POINT *sQ = get_sP();
    ibe_ec_store_sk(sQ, get_user()->get_id(), get_user()->get_mpk_filename());
}
