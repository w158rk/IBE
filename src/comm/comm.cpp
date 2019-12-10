/**
 * filename : comm.cpp 
 * functions 
 *      - getter and setter of Comm class 
 *      - interface functions like connect_to_server and send 
 */


#include<stdio.h>
#include<comm.hpp>
#include<ui.hpp>

#include <sstream>

extern "C" 
{
    #include"comm_lcl.h"
}

using namespace comm;


#define Error(err) throw CommException(err)

void Comm::connect_to_server(char* ip_addr, int port)
{
    if(-1 != connect_socket_server(ip_addr, port, &m_read_file, &m_write_file))
    {
        m_fread_file = true;
        m_fwrite_file = true;
        return ;
    }

    std::ostringstream s;
    s << "can not connect to server " << ip_addr 
        << " : " << port << std::endl;
    Error(s.str());

}

int Comm::send(const void *vptr, size_t n)
{
    FILE *write_file = get_write_file();

    return Write(fileno(write_file), vptr, n);    

}


Comm::Comm() 
{   
    Comm::cnt ++; 
    ui::UInterface::debug("delete Comm");
}

Comm::~Comm() 
{
    Comm::cnt --; 

    std::ostringstream s;
    s << "delete Comm" << std::endl;
    s << "the rest of Comm object: " << Comm::cnt << std::endl;

    ui::UInterface::debug(s.str());
}

GET_AND_SET_IMPL(Comm, FILE *, read_file)
GET_AND_SET_IMPL(Comm, FILE *, write_file)
GET_AND_SET_IMPL(Comm, interface::IPacket *, packet_ptr)
GET_AND_SET_IMPL(Comm, user::User *, user_ptr)
GET_AND_SET_IMPL(Comm, interface::IUI *, ui_ptr)
GET_AND_SET_IMPL(Comm, std::thread *, thread)
GET_AND_SET_IMPL(Comm, char *, err_sig)
GET_AND_SET_IMPL(CommException, std::string, message)

int Comm::cnt = 0;