#ifndef PACKET_LCL_HPP 
#define PACKET_LCL_HPP 

#include<packet.hpp>
#include <unordered_map>
#include <set>

namespace packet
{
    
    char *user_get_mpk_filename(user::User *user);
    char *user_get_msk_filename(user::User *user);
    char *user_get_sk_filename(user::User *user);
    char *user_get_cfg_filename(user::User *user);
    ID *user_get_id(user::User *);
    int user_get_mpk_len(user::User *user);
    int user_get_msk_len(user::User *user);
    int user_get_sk_len(user::User *user);
    void user_set_sm4_key(user::User *user, char *key);
    char *user_get_sm4_key(user::User *user);
    init::Initializer *user_get_init(user::User *user);

    init::Initializer *init_new(Packet *packet);
    std::unordered_map<ID*, BIGNUM*> *init_get_numbers(init::Initializer *);
    std::unordered_map<ID*, EC_POINT*> *init_get_sp_pub_points(init::Initializer *);
    std::unordered_map<ID*, EC_POINT*> *init_get_sq_pub_points(init::Initializer *);
    std::unordered_map<ID*, point_t*> *init_get_sp2_pub_points(init::Initializer *);
    std::set<ID*> *init_get_user_ids(init::Initializer *);
    void init_run(init::Initializer *init);


}


#endif