#ifndef INIT_HPP 
#define INIT_HPP 

#include<interface.hpp>

#include<utils.h>
#include<ss.h>
#include<set>
#include<openssl/bn.h>

#include<unordered_map>

namespace init
{
    struct config_t 
    {
        bool is_set;
        int user_cnt;
        std::set<ID*> user_ids;
    };


    class Initializer 
    {
        public:
            GET_AND_SET(interface::IUser *, user)
            GET_AND_SET2(std::unordered_map<ID*, BIGNUM*>*, numbers)
            GET_AND_SET(std::set<EC_POINT*>, sp_pub_points)
            GET_AND_SET(std::set<EC_POINT*>, sq_pub_points)
            GET_AND_SET(SS_POLY*, poly)
            GET_AND_SET(BIGNUM*, share)

            void run();
            struct config_t *get_config();

            Initializer(interface::IUser *user);

        private:

            DECLARE_MEMBER(interface::IUser *, user)
            DECLARE_MEMBER(BIGNUM*, share)
            DECLARE_MEMBER2(std::unordered_map<ID*, BIGNUM*>*, numbers)
            DECLARE_MEMBER(std::set<EC_POINT*>, sp_pub_points)
            DECLARE_MEMBER(std::set<EC_POINT*>, sq_pub_points)
            DECLARE_MEMBER(SS_POLY*, poly)

            struct config_t config;
            void read_config();
            void gen_poly();
            void cal_fx(char* result, int *len, ID* id);
            void cal_share();
            void cal_shareP(char *result, int *len);
            void cal_shareQ(char *result, int *len, ID* id);
            void cal_share_with_lp();
    };

    class InitException : public RootException 
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