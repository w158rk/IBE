#include<app.hpp>
#include<iostream>

using namespace app;

Client::Client(std::string ip_address, int port, ID* id)
    :User(ip_address, port, id)
{
    
}

Client::~Client()
{
    
}