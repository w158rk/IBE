#include "packet_lcl.hpp"
#include <user.hpp>

using namespace packet;
using namespace user;

// const char *packet::user_get_global_filename() 
// {
//     return "mpk-global.conf";
// }

char *packet::user_get_mpk_filename(user::User *user)
{
    return user->get_mpk_filename();
}

char *packet::user_get_msk_filename(user::User *user)
{
    return user->get_msk_filename();
}

char *packet::user_get_sk_filename(user::User *user)
{
    return user->get_sk_filename();
}

int packet::user_get_mpk_len(user::User *user)
{
    return user->get_mpk_len();
}


int packet::user_get_msk_len(user::User *user)
{
    return user->get_msk_len();
}


int packet::user_get_sk_len(user::User *user)
{
    return user->get_sk_len();
}



void packet::user_set_sm4_key(user::User *user, char *key)
{
    user->set_sm4_key(key);
}

init::Initializer *packet::user_get_init(user::User *user)
{
    user->get_initializer();
}

ID *packet::user_get_id(User *user)
{
    return user->get_id();
}


char *packet::user_get_cfg_filename(user::User *user)
{
    return user->get_cfg_filename();
}

char *packet::user_get_sm4_key(user::User *user)
{
    return user->get_sm4_key();
}
