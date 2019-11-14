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
GET_AND_SET_IMPL(User, init::Initializer*, initializer)
