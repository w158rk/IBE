#include "init_lcl.hpp"
#include <user.hpp>

using namespace init;
using namespace user;

char *init::user_get_mpk_filename(user::User *user)
{
    return user->get_mpk_filename();
}

ID *init::user_get_id(User *user)
{
    return user->get_id();
}

void init::user_set_init(Initializer *init, User *user)
{
    user->set_initializer(init);
}

char *init::user_get_cfg_filename(user::User *user)
{
    return user->get_cfg_filename();
}

void init::user_send_init_message_1(User* user, char *buf, int len, ID *id) 
{
    user->send_init_message_1(buf, len, id);
}

void init::user_send_init_message_2(User* user, char *buf, int len1, int len2, ID *id) 
{
    user->send_init_message_2(buf, len1, len2, id);
}

void init::user_send_init_message_3(User* user, char *buf, int len, ID *id) 
{
    user->send_init_message_3(buf, len, id);
}