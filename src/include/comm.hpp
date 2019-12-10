#ifndef COMM_HPP
#define COMM_HPP

#include <interface.hpp>
#include <stdlib.h>
#include <utils.h>

namespace comm 
{

    class Comm : public interface::IComm 
    {
        friend class interface::IComm;

    public : 

        static int cnt;
    
        Comm(   FILE *read_file, 
                FILE *write_file, 
                interface::IPacket *packet_ptr,
                user::User *user_ptr);
        Comm(   interface::IPacket *packet_ptr,
                user::User *user_ptr);
        Comm();
        ~Comm(); 
        
        void connect_to_server(char* ip_addr, int port);
        int send(const void *vptr, size_t n);
        void socket_main();
        static void file_main(user::User *user, 
					std::FILE *read_file, 
					std::FILE *write_file); 


        GET_AND_SET(FILE *, read_file)
        GET_AND_SET(FILE *, write_file)
        GET_AND_SET(interface::IPacket *, packet_ptr)
        GET_AND_SET(user::User *, user_ptr)
        GET_AND_SET(interface::IUI *, ui_ptr)
        GET_AND_SET(std::thread *, thread)
        GET_AND_SET(char *, err_sig)

    private :
        
        DECLARE_MEMBER(FILE *, read_file)
        DECLARE_MEMBER(FILE *, write_file)
        DECLARE_MEMBER(interface::IPacket *, packet_ptr)
        DECLARE_MEMBER(user::User *, user_ptr)
        DECLARE_MEMBER(char *, err_sig)
        DECLARE_MEMBER(interface::IUI *, ui_ptr)
        DECLARE_MEMBER(std::thread *, thread)


        int run_listen_core();
        void file_listener_run();
        void file_listener_run_internal();
        void socket_listener_run();

    };

    class CommException : RootException 
    {
    public:
        CommException(std::string message)
        {
            set_message(message);
        }
        CommException() = default;
        ~CommException() = default;

        GET_AND_SET(std::string, message)
        std::string what(){
            if(m_fmessage)
            {
                std::string rtn("error in comm module : ");
                rtn.append(m_message);
                return rtn;
            }
            return std::string("error in comm module");
        }
    private: 
        DECLARE_MEMBER(std::string, message)
    };
        
}

#endif