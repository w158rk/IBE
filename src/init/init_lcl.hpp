#ifndef INIT_LCL_HPP 
#define INIT_LCL_HPP 

#include<init.hpp>

namespace init
{
    
    char *user_get_mpk_filename(user::User *user);
    char *user_get_sk_filename(user::User *user);
    char *user_get_cfg_filename(user::User *user);
    ID *user_get_id(user::User *);

    void user_set_init(Initializer *init, user::User *);
    void user_send_init_message_1(user::User* user, char *buf, int len, ID *id);
    void user_send_init_message_2(user::User* user, char *buf, int len, int, ID *id);
    void user_send_init_message_3(user::User* user, char *buf, int len, ID *id);
    void user_sys_setup(user::User* user);

}


#endif