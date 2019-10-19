#include<app.hpp>

using namespace app;

Server::Server(std::string ip_address, int port, ID* id)
    :User(ip_address, port, id)
{

}

Server::~Server()
{
    
}