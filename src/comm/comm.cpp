#include<stdio.h>
#include<comm.hpp>
#include<interface.hpp>

extern "C" 
{
    #include"comm_lcl.h"
}

using namespace comm;

Comm::Comm( interface::IPacket *packet_ptr,
            interface::IUser *user_ptr)
{
    set_packet_ptr(packet_ptr);
    set_user_ptr(user_ptr);
}

Comm::Comm( FILE *read_file, 
            FILE *write_file, 
            interface::IPacket *packet_ptr,
            interface::IUser *user_ptr)
    :Comm(packet_ptr, user_ptr)
{
    set_read_file(read_file);
    set_write_file(write_file);
}

int Comm::connect_to_server(char* ip_addr, int port)
{
    if(-1 != connect_socket_server(ip_addr, port, &m_read_file, &m_write_file))
    {
        m_fread_file = true;
        m_fwrite_file = true;
    }
}

int Comm::send(const void *vptr, size_t n)
{
    FILE *write_file = get_write_file();
    Write(fileno(write_file), vptr, n);    
}