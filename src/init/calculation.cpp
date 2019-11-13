#include <utils.hpp>
#include <init.hpp>

#ifdef DEBUG 
#include <sstream>
#endif

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
    

    char *temp = NULL;
    temp = SS_bn2str(res);
    if(temp == NULL)
    {
        ERROR("cannot convert the big number to string");
    }

    /* we assume the function will return a string end with '\0' */
    int length = strlen(temp);

#ifdef DEBUG
    std::ostringstream s;
    s << "the length of the BN string: " << length << std::endl;
    get_user()->get_ui_ptr()->debug(s.str());
#endif

    *len = length;

    BN_free(x);
    BN_free(res);
}

void Initializer::cal_share()
{
    // just add all of the values in the vector `numbers`
    BIGNUM *sum = BN_new();
    BIGNUM *temp = BN_new();
    BN_zero(sum);

    for (BIGNUM* num : get_numbers())
    {
        BN_copy(temp, sum);
        BN_mod_add_sm9(sum, num, temp);
    }

    set_share(sum);

    BN_free(sum);
    BN_free(temp);
}

void Initializer::cal_shareP(char *result, int *len)
{
    // CURRENT CURRENT CURRENT CURRENT CURRENT CURRENT 
    // CURRENT CURRENT CURRENT CURRENT CURRENT CURRENT 
    // CURRENT CURRENT CURRENT CURRENT CURRENT CURRENT 
}

void Initializer::cal_shareQ(char *result, int *len, ID *id)
{
    
}
