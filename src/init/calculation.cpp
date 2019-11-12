#include <utils.hpp>
#include <init.hpp>

using namespace init;

#define ERROR(err) get_user()->get_ui_ptr()->error(err)

void Initializer::gen_poly()
{

    SS_POLY *poly = SS_POLY_new();

    if(!SS_poly_rand_sm9(poly, config.user_cnt))
    {
        ERROR("can not generate a polynomial");
    }

    set_poly(poly);

}

void Initializer::cal_fx(char* result, int *len, ID* id)
{
    // pre-condition, the poly is set 
    if(!m_fpoly)
    {
        ERROR("the polynomial is not set");
    }


    BIGNUM *x = BN_new();
    SS_id2num_init(x, id, get_user()->get_mpk_filename());
    BIGNUM *res = BN_new();
    SS_poly_apply_sm9(res, get_poly(), x);

    BN_free(x);
    BN_free(res);
}
