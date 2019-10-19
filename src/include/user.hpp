#ifndef USER__H
#define USER__H

#include<string>
#include<ds.h>
#include<interface.hpp>
#include<utils.h>

namespace user {

    class User : interface::IUser
    {

    public :

        User(std::string ip_address, int port, ID* id);
        int run();

        ~User();

        GET_AND_SET(interface::IComm *, comm_ptr)
        GET_AND_SET(interface::IPacket *, packet_ptr)
        GET_AND_SET(interface::IUI *, ui_ptr)
        GET_AND_SET(std::string, ip_address)
        GET_AND_SET(int, port)
        GET_AND_SET(ID*, id)
        GET_AND_SET(char *, err_sig)

        int run_send_message(char *dest_ip, 
							int dest_port,
							ID *dest_id);

    private :
        DECLARE_MEMBER(interface::IComm *, comm_ptr)
        DECLARE_MEMBER(interface::IPacket *, packet_ptr)
        DECLARE_MEMBER(interface::IUI *, ui_ptr)
        DECLARE_MEMBER(std::string, ip_address)
        DECLARE_MEMBER(int, port)
        DECLARE_MEMBER(ID*, id)
        DECLARE_MEMBER(char *, err_sig)

        void socket_main();
        void file_main();

    };

    class Server : public User
    {

    public :

        Server(std::string ip_address, int port, ID* id);
        ~Server();
    };

    class Client : public User 
    {
    
    public:

        Client(std::string ip_address, int port, ID* id);
        ~Client();

        int run_get_private_key(char *server_ip, 
								int server_port,
								ID *server_id=nullptr);



    };


};

#endif