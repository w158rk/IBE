#include<stdio.h>
#include<comm.hpp>
#include<interface.hpp>

extern "C" 
{
    #include"comm_lcl.h"
}

using namespace comm;


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

    return Write(fileno(write_file), vptr, n);    

}