#include <config.h>
#include <utils.hpp>
#include <init.hpp>

#ifdef DEBUG 
#include <sstream>
#endif

using namespace init;

#define Error(err) throw InitException(err)

# ifdef DEBUG
# define Debug(err) get_user()->get_ui_ptr()->debug(err)
# endif

void Initializer::gen_poly()
{

    SS_POLY *poly = SS_POLY_new();

    if(!SS_poly_rand_sm9(poly, config.user_cnt))
    {
        Error("can not generate a polynomial");
    }

    set_poly(poly);

}

void Initializer::cal_fx(char* result, int *len, ID* id)
{
    // pre-condition, the poly is set 
    if(!m_fpoly)
    {
        Error("the polynomial is not set");
    }


    BIGNUM *x = BN_new();
    SS_id2num_init(x, id, get_user()->get_mpk_filename());
    BIGNUM *res = BN_new();
    SS_poly_apply_sm9(res, get_poly(), x);
    

    char *temp = NULL;
    temp = SS_bn2str(res);
    if(temp == NULL)
    {
        Error("cannot convert the big number to string");
    }

    /* we assume the function will return a string end with '\0' */
    int length = strlen(temp);

#ifdef DEBUG
    std::ostringstream s;
    s << "the length of the BN string: " << length << std::endl;
    get_user()->get_ui_ptr()->debug(s.str());
#endif

    // set the results
    std:memcpy(result, temp, length);
    *len = length;

    std::free(temp);
    BN_free(x);
    BN_free(res);
}

void Initializer::cal_share()
{
    // just add all of the values in the vector `numbers`
    BIGNUM *sum = BN_new();
    BIGNUM *temp = BN_new();
    BIGNUM *tmp2 = NULL; 
    BN_zero(sum);

    for ( auto& num : *get_numbers())
    {
        BN_copy(temp, sum);
        BN_mod_add_sm9(sum, num.second, temp);
    }

    char tmp_str[BUFFER_SIZE];
    int length;

    // calc fi(xi) 
    cal_fx(tmp_str, &length, get_user()->get_id());

# ifdef DEBUG
    std::ostringstream s;
    s << "the length of the BN string: " << length << std::endl;
    Debug((s.str()));
# endif

    if(!SS_str2bn(&tmp2, tmp_str))
    {
        throw InitException("can not convert hex to bn");
    }

    // add to the sum
    BN_copy(temp, sum);
    BN_mod_add_sm9(sum, tmp2, temp);
    set_share(sum);

    BN_free(temp);
    BN_free(tmp2);
    BN_free(sum);
}

void Initializer::cal_share_with_lp()
{
    //update the share as share = share * lp 
    // first, calculate the value hashed from all of the id 
    // hj = id2num(IDj)
    BIGNUM **num_list = (BIGNUM **)std::malloc(config.user_cnt * sizeof(BIGNUM *));
    int j=0, i=-1;
    for (ID *id : config.user_ids)
    {
        if(ID_equal(id, get_user()->get_id()))
        {
            i = j;
        }
        num_list[j] = BN_new();
        SS_id2num_init(num_list[j], id, get_user()->get_mpk_filename());
        j ++;
    }

    if(i < 0)
    {
        Error("the list of hash values does not include the original user's");
    }

    // calculate li(0)
    BIGNUM *res = BN_new();
    BIGNUM *zero = BN_new();
    BN_zero(zero);
    SS_lagrange_value_sm9(res, num_list, config.user_cnt, i, zero);
    set_share(res);

    // free the values
    for (j=0; j<config.user_cnt; j++)
    {
        BN_free(num_list[j]);
    }
    BN_free(res);
    BN_free(zero);

}

void Initializer::cal_shareP(char *result, int *len)
{
    // calculate share * P
    EC_POINT *point = NULL;
    EC_GROUP *group = NULL;
    BN_CTX *ctx = BN_CTX_new();
    if(!ibe_cal_xP(&group, &point, get_share(), get_user()->get_mpk_filename()))
    {
        Error("calculate the xP failed");
    }

    char *temp = SS_ec2str(group, point, ctx);
    int length = strlen(temp);
    if (*len < length)
    {
        std::free(temp);
        EC_POINT_free(point);
        EC_GROUP_free(group);
        BN_CTX_free(ctx);

        Error("the buffer allocated is not enough");
    }
    *len = length;
    std::memcpy(result, temp, *len);

    std::free(temp);
    EC_POINT_free(point);
    EC_GROUP_free(group);
    BN_CTX_free(ctx);

}

void Initializer::cal_shareQ(char *result, int *len, ID *id)
{

    // calculate share * Q
    EC_POINT *point = NULL;
    EC_GROUP *group = NULL;
    EC_POINT *Q = NULL;
    BN_CTX *ctx = BN_CTX_new();
    if(!ibe_id2point_init(&Q, id->id, id->length, get_user()->get_mpk_filename()))
    {
        Error("calculate the Q failed");
    }

    if(!ibe_cal_xQ(&group, &point, get_share(), Q, get_user()->get_mpk_filename()))
    {
        Error("calculate the xP failed");
    }

    char *temp = SS_ec2str(group, point, ctx);
    int length = strlen(temp);

    if (*len < length)
    {
        std::free(temp);
        EC_POINT_free(point);
        EC_GROUP_free(group);
        BN_CTX_free(ctx);

        Error("the buffer allocated is not enough");
    }
    *len = length;
    std::memcpy(result, temp, *len);

    std::free(temp);
    EC_POINT_free(point);
    EC_POINT_free(Q);
    EC_GROUP_free(group);
    BN_CTX_free(ctx);
    
}
