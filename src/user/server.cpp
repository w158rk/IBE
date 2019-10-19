#include<user.hpp>

using namespace user;

Server::Server(std::string ip_address, int port, ID* id)
    :User(ip_address, port, id)
{

}

Server::~Server()
{
    
}