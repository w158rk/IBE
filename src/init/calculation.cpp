#include <config.h>
#include <cstring>
// #include <utils.hpp>
#include "init_lcl.hpp"
#include <ui.hpp>

#ifdef DEBUG 
#include <sstream>
#endif

using namespace init;

#define Error(err) throw InitException(err)

# ifdef DEBUG
# define Debug(err) ui::UInterface::debug(err)
# endif

void Initializer::gen_poly()
{

    SS_POLY *poly = SS_POLY_new();

    if(!SS_poly_rand_smx(poly, config.user_cnt))
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
    SS_id2num_init(x, id, user_get_mpk_filename(get_user()));
    BIGNUM *res = BN_new();
    if(0 == SS_poly_apply_smx(res, get_poly(), x))
    {
        Error("can not apply the x to the polynomial");
    }
    

    char *temp = nullptr;
    temp = BN_bn2str(res);
    if(temp == nullptr)
    {
        Error("cannot convert the big number to string");
    }

    /* we assume the function will return a string end with '\0' */
    int length = strlen(temp);

#ifdef DEBUG
    std::ostringstream s;
    s << "the length of the fx: " << length << std::endl;
    Debug(s.str());
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
    BIGNUM *tmp2 = nullptr; 
    BN_zero(sum);

    for ( auto& num : *get_numbers())
    {
        BN_copy(temp, sum);
        BN_mod_add_smx(sum, num.second, temp);
    }

    char tmp_str[BUFFER_SIZE];
    int length;

    // calc fi(xi) 
    cal_fx(tmp_str, &length, user_get_id(get_user()));

# ifdef DEBUG
    std::ostringstream s;
    s << "the length of the BN string: " << length << std::endl;
    Debug((s.str()));
# endif

    if(!BN_str2bn(&tmp2, tmp_str))
    {
        throw InitException("can not convert hex to bn");
    }

    // add to the sum
    BN_copy(temp, sum);
    BN_mod_add_smx(sum, tmp2, temp);
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
        if(ID_equal(id, user_get_id(get_user())))
        {
            i = j;
        }
        num_list[j] = BN_new();
        SS_id2num_init(num_list[j], id, user_get_mpk_filename(get_user()));
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
    SS_lagrange_value_smx(res, num_list, config.user_cnt, i, zero);
    set_share(res);

    // free the values
    for (j=0; j<config.user_cnt; j++)
    {
        BN_free(num_list[j]);
    }
    BN_free(res);
    BN_free(zero);

}

void Initializer::cal_shareP1(char *result, int *len)
{
    // calculate share * P
    EC_POINT *point = nullptr;
    EC_GROUP *group = nullptr;
    BN_CTX *ctx = BN_CTX_new();
    if(!ibe_ec_cal_xP1(&group, &point, get_share(), user_get_mpk_filename(get_user())))
    {
        Error("calculate the xP failed");
    }

    char *temp = ibe_ec2str(point, ctx);
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

void Initializer::cal_shareP2(char *out, int *outlen)
{
    // calculate share * P

	int length = *outlen;
	char buf[150];


	if(!out)
	{
		Error("the out buffer is not set");
	}
	if(length<129)
	{
		Error("the out buffer is not big enough");
	}
	length = 129;
	point_t *point = ibe_point_new();

    // calculate C = xP
	if (!ibe_point_cal_xP2(point, get_share(), user_get_mpk_filename(get_user()))) {
		Error("parse xP2 failed");
	}

#ifdef DEBUG 
	fprintf(stderr, "location of the point: 0x%lx\n", point);
	fprintf(stderr, "point on curve: %d\n", ibe_point_is_on_curve(point));
#endif

	if(!(ibe_point_to_octets(point, buf)))
	{
        ibe_point_free(point);
		Error("cannot convert the point to a string");
	}

	memcpy(out, buf, length);
	*outlen = length;
# ifdef DEBUG
    Debug("mark");
#endif

}


void Initializer::cal_shareQ(char *result, int *len, ID *id)
{

    // calculate share * Q
    EC_POINT *point = nullptr;
    EC_GROUP *group = nullptr;
    EC_POINT *Q = nullptr;
    BN_CTX *ctx = BN_CTX_new();
    if(!ibe_ec_id2point(&Q, id->id, id->length, user_get_mpk_filename(get_user())))
    {
        Error("calculate the Q failed");
    }

    if(!ibe_ec_cal_xQ(&group, &point, get_share(), Q, user_get_mpk_filename(get_user())))
    {
        Error("calculate the xP failed");
    }

    char *temp = ibe_ec2str(point, ctx);
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

void Initializer::cal_sP()
{
    // add the points in the sp_point with the product of the share and the P point 

    // calculate Ppub1 
#ifdef DEBUG 
    Debug("begin to calculate sP1");
#endif

    {    
        EC_POINT *point = nullptr;
        EC_GROUP *group = nullptr;
        BN_CTX *ctx = BN_CTX_new();
        EC_POINT *res = nullptr;
        EC_POINT *tmp = nullptr;


        // point = share * P1
        if(!ibe_ec_cal_xP1(&group, &point, get_share(), user_get_mpk_filename(get_user())))
        {
            Error("calculate the xP failed");
        }

        if(!(res = EC_POINT_new(group)))
        {
            Error("cannot alloacate the point");            
        }

        for (auto elem : *get_sp_pub_points())
        {
            tmp = elem.second;
            if(!EC_POINT_add(group, res, point, tmp, ctx)       
                ||!EC_POINT_copy(point, res))
            {
                EC_GROUP_free(group);
                BN_CTX_free(ctx);
                EC_POINT_free(point);
                EC_POINT_free(res);
                Error("calculate the sP failed in the loop");
            }
        }

        set_sP(res);
        EC_POINT_free(point);
        BN_CTX_free(ctx);

    }    
#ifdef DEBUG 
    Debug("begin to calculate sP2");
#endif
    
    // Ppub2
    {
        point_t *point = ibe_point_new();
        point_t *res = ibe_point_new();

        // point = share * P2
        try 
        {
            if(!ibe_point_cal_xP2(point, get_share(), user_get_mpk_filename(get_user())))
            {
                Error("calculate the xP failed");
            }

            for (auto elem : *get_sp2_pub_points())
            {
#ifdef DEBUG 
                Debug("round mark");
#endif
                point_t *tmp = elem.second;
                if(!ibe_point_add(res, point, tmp)
                    ||!ibe_point_copy(point, res))
                {
                    Error("calculate the sP failed in the loop");
                }
            }
        }
        catch (InitException &e)
        {
            ibe_point_free(point);
            ibe_point_free(res);
            throw e;
        }

        set_Ppub2(res);
        ibe_point_free(point);
        
    }
    
}

void Initializer::cal_sQ()
{
    // add the points in the sq_point with the product of the share and the Q point 

    // calculate share * Q
    EC_POINT *point = nullptr;
    EC_POINT *Q = nullptr;
    EC_GROUP *group = nullptr;
    BN_CTX *ctx = BN_CTX_new();
    
    if(!ibe_ec_id2point(&Q, user_get_id(get_user())->id, user_get_id(get_user())->length, user_get_mpk_filename(get_user()))
        ||!ibe_ec_cal_xQ(&group, &point, get_share(), Q, user_get_mpk_filename(get_user())))
    {
        Error("calculate the xQ failed");
    }

    EC_POINT *res = EC_POINT_new(group);
    EC_POINT *tmp = nullptr;
    for (auto elem : *get_sq_pub_points())
    {
        tmp = elem.second;
        if(!EC_POINT_add(group, res, point, tmp, ctx)
            ||!EC_POINT_copy(point, res)
            ||!EC_POINT_add(group, res, point, tmp, ctx))
        {

            Error("calculate the sQ failed in the loop");
        }
    }

    bool is_to_free_point = true;
    if(!m_fsP)
    {
        set_sP(point);
        is_to_free_point = false;
    }
    else 
    {
        if(!EC_POINT_copy(m_sP, point))
        {
            Error("can not set the sP");
        }
    }

    if(is_to_free_point)
    {
        EC_POINT_free(point);
    }

    EC_GROUP_free(group);
    EC_POINT_free(Q);
    BN_CTX_free(ctx);


}