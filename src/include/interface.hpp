#ifndef INTERFACE_H
#define INTERFACE_H

#include<ds.hpp>
#include<utils.h>
#include<string>
#include<thread>

namespace init{
    class Initializer;    
    class InitException;
};

namespace user{
    class User;
    class UserException;
};


namespace comm{
    class Comm;
    class CommException;
};

namespace interface 
{
    class IPacket;
    class IComm;
    class IUI;
    class IUser;

    class IPacket 
    {

    public:
        virtual int packet_send(PacketCTX *ctx) = 0;
        virtual int packet_handle(PacketCTX *ctx) = 0;

        virtual ~IPacket() = default;
        VIRTUAL_GET_AND_SET(IComm *, comm_ptr)
        VIRTUAL_GET_AND_SET(user::User *, user_ptr)
        VIRTUAL_GET_AND_SET(IUI *, ui_ptr)
    };

    class IComm 
    {

    public:
        virtual int send(const void *vptr, size_t n) = 0;
        virtual void connect_to_server(char* ip_addr, int port) = 0;
        
        virtual void socket_main() = 0;

        virtual ~IComm() = default;

        static void file_main(user::User *user, 
					std::FILE *read_file, 
					std::FILE *write_file); 

        VIRTUAL_GET_AND_SET(IPacket *, packet_ptr)
        VIRTUAL_GET_AND_SET(user::User *, user_ptr)
        VIRTUAL_GET_AND_SET(IUI *, ui_ptr)
        VIRTUAL_GET_AND_SET(std::FILE *, read_file)
        VIRTUAL_GET_AND_SET(std::FILE *, write_file)

    };



    class IUI
    {

    public:
        void virtual run() = 0;
        static void print(std::string message);
        static void error(std::string message);
        static void debug(std::string message);
        static void print(char *message, int length);
        static void error(char *message, int length);
        static void debug(char *message, int length);
        virtual ~IUI() = default;
        VIRTUAL_GET_AND_SET(user::User *, user_ptr)
    };
    
} 

#endif