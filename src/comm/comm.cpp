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
    m_packet_ptr = packet_ptr;
    m_user_ptr = user_ptr;
    m_fpacket_ptr = true;
    m_fuser_ptr = true;
}

Comm::Comm( FILE *read_file, 
            FILE *write_file, 
            interface::IPacket *packet_ptr,
            interface::IUser *user_ptr)
    :Comm(packet_ptr, user_ptr)
{
    m_read_file = read_file;
    m_fread_file = true;
    m_write_file = write_file;
    m_fwrite_file = true;
}

int Comm::send(int fd, const void *vptr, size_t n)
{
    Write(fd, vptr, n);    
}