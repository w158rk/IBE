#include<user.hpp>
#include<iostream>

using namespace user;

Client::Client(std::string ip_address, int port, ID* id)
    :User(ip_address, port, id)
{
    
}

Client::~Client()
{
    
}