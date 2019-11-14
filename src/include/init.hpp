#ifndef INIT_HPP 
#define INIT_HPP 

#include<utils.h>
#include<ss.h>
#include<set>
#include<openssl/bn.h>

# include<interface.hpp>

namespace init
{
    class Initializer 
    {
        public:
            GET_AND_SET(interface::IUser *, user)
            GET_AND_SET(std::set<BIGNUM*>, numbers)
            GET_AND_SET(std::set<EC_POINT*>, sp_pub_points)
            GET_AND_SET(std::set<EC_POINT*>, sq_pub_points)
            GET_AND_SET(SS_POLY*, poly)
            GET_AND_SET(BIGNUM*, share)

            void run();

            Initializer(interface::IUser *user);

        private:

            DECLARE_MEMBER(interface::IUser *, user)
            DECLARE_MEMBER(BIGNUM*, share)
            DECLARE_MEMBER(std::set<BIGNUM*>, numbers)
            DECLARE_MEMBER(std::set<EC_POINT*>, sp_pub_points)
            DECLARE_MEMBER(std::set<EC_POINT*>, sq_pub_points)
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
            void cal_share_with_lp();
    };

    class InitException : public std::exception 
    {
    public:
        InitException(std::string message)
        {
            set_message(message);
        }
        InitException() = default;
        ~InitException() = default;

        GET_AND_SET(std::string, message)
        std::string what(){
            if(m_fmessage)
            {
                std::string rtn("error in Init module : ");
                rtn.append(m_message);
                return rtn;
            }
            return std::string("error in Init module");
        }
    private: 
        DECLARE_MEMBER(std::string, message)
    };


} // namespace init



#endif