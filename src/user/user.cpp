#include<iostream>
#include<user.hpp>

extern "C" {
    #include<comm.h>
}

using namespace user;

User::User(ID* id)
{
    // init the ID of this user
    set_ip_address(id->ip);
    set_port(id->port);
    set_id(id);

}


User::~User() 
{
    
}