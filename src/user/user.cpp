#include<iostream>
#include<user.hpp>

extern "C" {
    #include<comm.h>
}

using namespace user;

User::User(ID* id)
{
    // init the ID of this user
    m_initializer = nullptr;
    set_ip_address(id->ip);
    set_port(id->port);
    set_id(id);

}


User::~User() 
{
    
}

GET_AND_SET_IMPL(User, interface::IUI *, ui_ptr)
GET_AND_SET_IMPL(User, std::string, ip_address)
GET_AND_SET_IMPL(User, int, port)
GET_AND_SET_IMPL(User, ID*, id)
GET_AND_SET_IMPL(User, char *, err_sig)
GET_AND_SET_IMPL(User, char *, msk_filename)
GET_AND_SET_IMPL(User, char *, msk_len_file)
GET_AND_SET_IMPL(User, char *, mpk_len_file)
GET_AND_SET_IMPL(User, char *, cfg_filename)
GET_AND_SET_IMPL(User, char *, mpk_filename)
GET_AND_SET_IMPL(User, interface::IComm *, comm_ptr)
GET_AND_SET_IMPL(User, interface::IPacket *, packet_ptr)
GET_AND_SET_IMPL(User, char *, sm4_key)
GET_AND_SET_IMPL(User, std::thread *, thread)
GET_AND_SET_IMPL(UserException, std::string, message)
GET_AND_SET_IMPL(User, long, mpk_len)
GET_AND_SET_IMPL(User, long, msk_len)
GET_AND_SET_IMPL(User, long, sk_len)
GET_AND_SET_IMPL(User, User::user_mode_t, user_mode)
GET_AND_SET_IMPL(User, init::Initializer*, initializer)

char *User::get_sk_filename()
{
    ID *id = get_id();
    int filename_len = id->length;    
    char *filename = NULL;  

    switch (get_user_mode())
    {
    case USER_INIT_CLIENT:
    case USER_INIT_SERVER:

        filename_len += 16;
        filename = (char *)malloc(filename_len);  

        filename[0] = 's';      
        filename[1] = 'k';
        filename[2] = '-';
        filename[3] = 'g';
        filename[4] = 'l';
        filename[5] = 'o';
        filename[6] = 'b';
        filename[7] = 'a';
        filename[8] = 'l';
        filename[9] = '_';
        memcpy(filename+10, (id->id), (id->length));
        filename[filename_len-6] = '.'; 
        filename[filename_len-5] = 'c'; 
        filename[filename_len-4] = 'o'; 
        filename[filename_len-3] = 'n'; 
        filename[filename_len-2] = 'f';
        filename[filename_len-1] = '\0';

        break;
    
    default:
        filename_len += 9;    
        filename = (char *)malloc(filename_len);  
        
        filename[0] = 's';      
        filename[1] = 'k';
        filename[2] = '_';
        memcpy(filename+3, (id->id), (id->length));
        filename[filename_len-6] = '.'; 
        filename[filename_len-5] = 'c'; 
        filename[filename_len-4] = 'o'; 
        filename[filename_len-3] = 'n'; 
        filename[filename_len-2] = 'f';
        filename[filename_len-1] = '\0';
    }

    return filename;
}