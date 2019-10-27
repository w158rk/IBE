#ifndef COMM_HPP
#define COMM_HPP

#include <interface.hpp>
#include <stdlib.h>
#include <utils.h>

namespace comm 
{

    class Comm : public interface::IComm 
    {
    public : 
    
        Comm(   FILE *read_file, 
                FILE *write_file, 
                interface::IPacket *packet_ptr,
                interface::IUser *user_ptr);
        Comm(   interface::IPacket *packet_ptr,
                interface::IUser *user_ptr);
        Comm() = default;
        ~Comm() = default;
        
        int connect_to_server(char* ip_addr, int port);
        int send(const void *vptr, size_t n);
        void socket_main();
        void file_main();


        GET_AND_SET(FILE *, read_file)
        GET_AND_SET(FILE *, write_file)
        GET_AND_SET(interface::IPacket *, packet_ptr)
        GET_AND_SET(interface::IUser *, user_ptr)
        GET_AND_SET(char *, err_sig)

    private :
        
        DECLARE_MEMBER(FILE *, read_file)
        DECLARE_MEMBER(FILE *, write_file)
        DECLARE_MEMBER(interface::IPacket *, packet_ptr)
        DECLARE_MEMBER(interface::IUser *, user_ptr)
        DECLARE_MEMBER(char *, err_sig)


        int run_listen_core();
        void file_listener_run();
        void socket_listener_run();

    };
    
}

#endif