#ifndef INIT_HPP 
#define INIT_HPP 

#include<utils.h>
#include<ss.h>
#include<interface.hpp>
#include<set>
#include<openssl/bn.h>

namespace init
{
    class Initializer 
    {
        public:
            GET_AND_SET(interface::IUser *, user)
            GET_AND_SET(std::set<BIGNUM>, numbers)
            GET_AND_SET(std::set<EC_POINT>, sp_pub_points)
            GET_AND_SET(std::set<EC_POINT>, sq_pub_points)
            GET_AND_SET(SS_POLY*, poly)
            GET_AND_SET(BIGNUM*, share)

            void run();

            Initializer(interface::IUser *user);

        private:

            DECLARE_MEMBER(interface::IUser *, user)
            DECLARE_MEMBER(BIGNUM*, share)
            DECLARE_MEMBER(std::set<BIGNUM>, numbers)
            DECLARE_MEMBER(std::set<EC_POINT>, sp_pub_points)
            DECLARE_MEMBER(std::set<EC_POINT>, sq_pub_points)
            DECLARE_MEMBER(SS_POLY*, poly)

            struct config_t 
            {
                bool is_set;
                int user_cnt;
                std::set<ID*> user_ids;
            }   config;

            void read_config();
            void gen_poly();
            void cal_fx(char* result, int *len, ID* id);
            void cal_share();
            void cal_shareP(char *result, int *len);
            void cal_shareQ(char *result, int *len, ID* id);

    };
} // namespace init



#endif